# How to test SAML as a developer without a server

https://capriza.github.io/samling/samling.html (https://github.com/capriza/samling) is a great
resource for being able to tinker with the SAML options within Synapse without needing to
deploy and configure a complicated software stack.

To make Synapse (and therefore Riot) use it:

1. Use the samling.html URL above or deploy your own and visit the IdP Metadata tab.
2. Copy the XML to your clipboard.
3. On your Synapse server, create a new file `samling.xml` next to your `homeserver.yaml` with
   the XML from step 2 as the contents.
4. Edit your `homeserver.yaml` to include:
   ```yaml
   saml2_config:
     sp_config:
       allow_unknown_attributes: true  # Works around a bug with AVA Hashes: https://github.com/IdentityPython/pysaml2/issues/388
       metadata:
         local: ["samling.xml"]   
   ```
5. Ensure that your `homeserver.yaml` has a setting for `public_baseurl`:
   ```yaml
   public_baseurl: http://localhost:8080/
   ```
6. Run `apt-get install xmlsec1` and `pip install --upgrade --force 'pysaml2>=4.5.0'` to ensure
   the dependencies are installed and ready to go.
7. Restart Synapse.

Then in Riot:

1. Visit the login page with a Riot pointing at your homeserver.
2. Click the Single Sign-On button.
3. On the samling page, enter a Name Identifier and add a SAML Attribute for `uid=your_localpart`.
   The response must also be signed.
4. Click "Next".
5. Click "Post Response" (change nothing).
6. You should be logged in.

If you try and repeat this process, you may be automatically logged in using the information you
gave previously. To fix this, open your developer console (`F12` or `Ctrl+Shift+I`) while on the
samling page and clear the site data. In Chrome, this will be a button on the Application tab.
