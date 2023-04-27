FROM mcr.microsoft.com/dotnet/sdk:6.0

# Install zip
RUN apt-get update && apt-get install zip -y
    
# Install az
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

RUN az version

# Build Function(s)
WORKDIR /build

RUN echo "#!/bin/bash\n" \
         "az ad signed-in-user show\n" \
         "if [ $? -ne 0 ]; then\n" \
         "  az login\n" \
         "fi\n" \
         "mkdir /out\n" \
         "cd /src\n" \
         "dotnet publish --output /out --configuration release --no-self-contained\n" \
         "cd /out && zip -r function.zip .\n" \
         "echo \"executing: 'az functionapp deployment source config-zip -g \${RESOURCE_GROUP} -n \${FUNCTION_NAME} --src function.zip --verbose'\"\n" \
         "az functionapp deployment source config-zip -g \${RESOURCE_GROUP} -n \${FUNCTION_NAME} --src function.zip --verbose\n" > /build/build.sh
         
RUN chmod +x /build/build.sh

CMD ["/bin/bash", "-c", "/build/build.sh"] 
