using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Azure.Core;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Secrets;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Management.Dns;
using Microsoft.Azure.Management.Dns.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Rest;

namespace TomCore.Tls.Functions.CertificateGeneration
{
    public class AcmeCertificateGeneration
    {
        // We are using an unusual time because Let's Encrypt gets overwhelmed with requests at e.g. midnight:
        // https://community.letsencrypt.org/t/new-service-busy-responses-beginning-during-high-load/184174
        private const string RunEveryCron = "17 01 23 * * 1"; // 23:01:17 UTC every Monday 

        private readonly ILogger _logger;
        private readonly Uri _acmeUri;

        public AcmeCertificateGeneration(Uri acmeUri, ILogger logger)
        {
            _logger = logger;
            _acmeUri = acmeUri;
        }

        [Function(nameof(AcmeCertificateGeneration))]
        public static Task Run([TimerTrigger(RunEveryCron)] TimerInfo myTimer, FunctionContext context)
        {
            var logger = context.GetLogger(nameof(AcmeCertificateGeneration));
            try
            {
                logger.LogInformation("{Nameof} is starting", nameof(AcmeCertificateGeneration));
                var acmeAccountData = ConfigurationReader.GetAcmeAccountDataConfiguration(logger);
                var dnsChallenges = ConfigurationReader.GetCertificateOrderInfosConfiguration(logger);

                if (dnsChallenges.Length == 0)
                {
                    logger.LogInformation("No Dns Challenges configured");
                    return Task.CompletedTask;
                }
                
                var instance = new AcmeCertificateGeneration(WellKnownServers.LetsEncryptV2, logger);
                return instance.RunDnsChallenges(acmeAccountData, dnsChallenges);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Exception while executing: {Message}", ex.Message);
                throw;
            }
        }

        private async Task<AcmeContext> GetContextForExistingAcmeAccount(string accountKeyAsPem)
        {
            _logger.LogInformation("Found Existing Account. Creating Acme Context");
            var accountKey = KeyFactory.FromPem(accountKeyAsPem);
            var acmeContext = new AcmeContext(_acmeUri, accountKey);
            var account = await acmeContext.Account();
            _logger.LogInformation("Account Location: {Location}", account.Location);
            return acmeContext;
        }

        private async Task<AcmeContext> GetContextForNewAcmeAccount(string email, Func<string, Task> storeAccountKeyAsPem)
        {
            _logger.LogInformation("Creating New Acme Account and Context");
            var acmeContext = new AcmeContext(_acmeUri);
            await acmeContext.NewAccount(email, true);
            var pemKey = acmeContext.AccountKey.ToPem();
            _logger.LogInformation("Storing account info in Azure KeyVault");
            await storeAccountKeyAsPem(pemKey);
            return acmeContext;
        }

        private async Task<AcmeContext> GetOrCreateAcmeAccountContext(Uri keyVaultUri, string email)
        {
            var secretClient = new SecretClient(keyVaultUri, new DefaultAzureCredential());
            var accName = "acme-account-" + _acmeUri.Host.Replace(".", "").Replace("-", "");
            _logger.LogInformation("Getting Acme account info from Azure KeyVault ({AccName})", accName);
            return
                await OnResponse.Get<AcmeContext>()
                    .ForCode(404, () => GetContextForNewAcmeAccount(email, accountKeyAsPem => secretClient.SetSecretAsync(accName, accountKeyAsPem)))
                    .Evaluate(() => secretClient.GetSecretAsync(accName), response => GetContextForExistingAcmeAccount(response.Value.Value));
        }

        public async Task RunDnsChallenges(AcmeAccountData acmeAccountData, IEnumerable<CertificateOrderInfo> certificateOrderInfo)
        {
            var accountContext = await GetOrCreateAcmeAccountContext(acmeAccountData.KeyVaultUri, acmeAccountData.AcmeAdminEmail);
            foreach (var orderInfo in certificateOrderInfo)
            {
                try
                {
                    await CreateCertificate(accountContext, orderInfo);
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Creating Certificate for {DomainName} failed", orderInfo.DomainName);
                }
            }
        }
        
        private static string GetSubdomainName(string zone, string subdomainFqdn)
        {
            if (subdomainFqdn.StartsWith("*."))
            {
                subdomainFqdn = subdomainFqdn.Remove(0, 2);
            }
            if (zone == subdomainFqdn)
            {
                return string.Empty;
            }

            string suffix = "." + zone;
            int index = subdomainFqdn.LastIndexOf(suffix, StringComparison.OrdinalIgnoreCase);

            if (index > 0)
            {
                return string.Concat(".", subdomainFqdn.AsSpan(0, index));
            }

            return string.Empty;
        }

        private async Task CreateCertificate(IAcmeContext accountContext, CertificateOrderInfo orderInfo)
        {
            var domainName = orderInfo.DomainName;

            _logger.LogInformation("Creating certificate for: {DomainName}", domainName);
            _logger.LogInformation("Testing access permissions for configured DNS Zone");
            await using (await SetDnsTxtChallenge(orderInfo, "_certGenerationTest", "testValue"))
            {
            }

            _logger.LogInformation("Creating order");
            var order = await accountContext.NewOrder(new[] {domainName});
            _logger.LogInformation("Starting Authorization");
            var authorizationContext = await order.Authorization(domainName);
            _logger.LogInformation("Getting DNS Authorization");
            var dnsChallenge = await authorizationContext.Dns();

            var dnsTxt = accountContext.AccountKey.DnsTxt(dnsChallenge.Token);

            var validationStartedAt = DateTime.Now;
            Challenge status;

            var dnsTxtChallenge = await SetDnsTxtChallenge(orderInfo, "_acme-challenge" + GetSubdomainName(orderInfo.ZoneName, orderInfo.DomainName), dnsTxt);
            await using (dnsTxtChallenge)
            {
                status = await ValidateChallenge(dnsChallenge);
                while (status.Status != ChallengeStatus.Invalid && status.Status != ChallengeStatus.Valid)
                {
                    var timePassed = DateTime.Now - validationStartedAt;
                    if (timePassed > TimeSpan.FromSeconds(30))
                    {
                        _logger.LogError("Timeout reached for validating challenge");
                        break;
                    }

                    _logger.LogInformation("Challenge still pending (status: {Status}). Time passed: {TimePassed}. Retrying in 500ms...", status.Status, timePassed);
                    await Task.Delay(500);
                    status = await ValidateChallenge(dnsChallenge);
                    _logger.LogInformation("Dns Challenge has status: {Status}", status.Status);
                }
            }

            if (status.Status != ChallengeStatus.Valid)
            {
                throw new Exception($"Validating challenge for {domainName} failed or timed out with status: {status.Error}");
            }

            _logger.LogInformation("Generating certificate");
            // Azure CDN only supports RSA for the private key
            var privateKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var cert = await order.Generate(new CsrInfo {CommonName = domainName}, privateKey);

            var pfxBuilder = cert.ToPfx(privateKey);
            var friendlyName = domainName + " Certificate";
            _logger.LogInformation("Converting to Pfx with friendly name: {FriendlyName}", friendlyName);
            var pfx = pfxBuilder.Build(friendlyName, String.Empty);

            _logger.LogInformation("Creating CertificateClient to KeyVault");
            var certificateClient = new CertificateClient(orderInfo.KeyVaultUri, new DefaultAzureCredential());

            _logger.LogInformation("Uploading certificate to KeyVault");
            await certificateClient.ImportCertificateAsync(new ImportCertificateOptions(NormalizeHostName(domainName), pfx));
            
            _logger.LogInformation("Finished creation for: {DomainName}", domainName);
        }

        private async Task<Challenge> ValidateChallenge(IChallengeContext challengeContext)
        {
            var location = challengeContext.Location;
            try
            {
                var status = await challengeContext.Validate();
                return status;
            }
            catch (Exception)
            {
                var result = await new HttpClient().GetAsync(location);
                _logger.LogInformation("Challenge failed with error: {Error}", result.Content.AsString());
                throw;
            }
        }
        
        private async Task<IAsyncDisposable> SetDnsTxtChallenge(CertificateOrderInfo orderInfo, string recordName, string dnsTxt)
        {
            _logger.LogDebug("Getting azure management token");
            var credential = new DefaultAzureCredential();
            var token = await credential.GetTokenAsync(new TokenRequestContext(new[] {"https://management.core.windows.net/.default"}));

            _logger.LogDebug("Creating DNSManagementClient");
            var dnsManagementClient = new DnsManagementClient(new TokenCredentials(token.Token)) {SubscriptionId = orderInfo.SubscriptionId};

            _logger.LogInformation("Setting Txt Record - ResourceGroup: {ResourceGroup} ZoneName: {ZoneName} RecordName: {RecordName}", orderInfo.ResourceGroupName, orderInfo.ZoneName, recordName);
            var recordSetParams = new RecordSet {TTL = 3600, TxtRecords = new List<TxtRecord> {new(new List<string> {dnsTxt})}};

            await dnsManagementClient.RecordSets.CreateOrUpdateAsync(
                orderInfo.ResourceGroupName,
                orderInfo.ZoneName,
                recordName,
                RecordType.TXT,
                recordSetParams);
            
            var validationStartedAt = DateTime.Now;
            while (true)
            {
                var retrievedRecordSet = await dnsManagementClient.RecordSets.GetAsync(
                    orderInfo.ResourceGroupName,
                    orderInfo.ZoneName, 
                    recordName, 
                    RecordType.TXT);

                if (retrievedRecordSet.TxtRecords.Count > 0)
                {
                    var recordFound = retrievedRecordSet.TxtRecords.Any(txtRecord => txtRecord.Value.Any(txtValue => txtValue == dnsTxt));
                    if (recordFound)
                    {
                        break;
                    }
                }

                var timePassed = DateTime.Now - validationStartedAt;
                if (timePassed > TimeSpan.FromSeconds(30))
                {
                    _logger.LogError("Timeout reached for validating correct txt content");
                    throw new Exception($"Validating txt content for zone {orderInfo.ZoneName} failed");
                }
                
                _logger.LogInformation("Could no retrieve correct txt content yet. Retrying");
                await Task.Delay(TimeSpan.FromMilliseconds(1000));
            }
            
            return new Disposer(() =>
            {
                _logger.LogInformation("Removing Txt Record - ResourceGroup: {ResourceGroup} ZoneName: {ZoneName} RecordName: {RecordName}", orderInfo.ResourceGroupName, orderInfo.ZoneName, recordName);
                return dnsManagementClient.RecordSets.DeleteAsync(orderInfo.ResourceGroupName, orderInfo.ZoneName, recordName, RecordType.TXT);
            });
        }

        private static string NormalizeHostName(string hostName) => hostName.Replace(".", "-").Replace("*","wildcard");
    }
}