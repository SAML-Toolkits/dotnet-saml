using System;
using System.Data;
using System.Configuration;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;

/// <summary>
/// AccountSettings
/// 
/// Replace this class with an interface to your own applications account settings. 
/// 
/// Each account should as a minimum have the following:
///  - A URL pointing to the identity provider for sending Auth Requests
///  - A X.509 certificate for validating the SAML Responses from the identity provider
/// 
/// These should be retrieved from the account store/database on each request in the authentication flow.
/// </summary>
public class AccountSettings
{
    public string certificate = "-----BEGIN CERTIFICATE-----\nMIIBrTCCAaGgAwIBAgIBATADBgEAMGcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApD\nYWxpZm9ybmlhMRUwEwYDVQQHDAxTYW50YSBNb25pY2ExETAPBgNVBAoMCE9uZUxv\nZ2luMRkwFwYDVQQDDBBhcHAub25lbG9naW4uY29tMB4XDTEwMDMwOTA5NTgzNFoX\nDTE1MDMwOTA5NTgzNFowZzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3Ju\naWExFTATBgNVBAcMDFNhbnRhIE1vbmljYTERMA8GA1UECgwIT25lTG9naW4xGTAX\nBgNVBAMMEGFwcC5vbmVsb2dpbi5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ\nAoGBANtmwriqGBbZy5Dwy2CmJEtHEENVPoATCZP3UDESRDQmXy9Q0Kq1lBt+KyV4\nkJNHYAAQ9egLGWQ8/1atkPBye5s9fxROtf8VO3uk/x/X5VSRODIrhFISGmKUnVXa\nUhLFIXkGSCAIVfoR5S2ggdfpINKUWGsWS/lEzLNYMBkURXuVAgMBAAEwAwYBAAMB\nAA==\n-----END CERTIFICATE-----";
    public string idp_sso_target_url = "https://app.onelogin.com/saml/signon/20219";
}
