docker run --name adjoin -d --restart=unless-stopped \
    -e AD_DOMAIN="sandbox.lab" \
    -e AD_USERNAME="sandbox\s-adjoiner" \
    -e USE_LDAPS="true" \
    -e SM_PROJECT="cbpetersen-sandbox" \
    -e SM_NAME_ADPASSWORD="adjoin-adpassword" \
    -e SM_VERSION_ADPASSWORD="latest" \
    -e SM_NAME_CACERT="adjoin-cacert" \
    -e SM_VERSION_CACERT="latest" \
    -e FUNCTION_IDENTITY="adjoin@cbpetersen-sandbox.iam.gserviceaccount.com" \
    -e PROJECTS_DN="OU=Projects,OU=sandbox.lab,DC=sandbox,DC=lab" \
    -e SERVER_WORKERS=33 \
    -e PORT=8080 \
    --network host \
    gcr.io/cbpetersen-sandbox/adjoin