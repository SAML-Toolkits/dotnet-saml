using System;
using System.Data;
using System.Configuration;
using System.Web;
using System.Web.Security;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.WebControls.WebParts;
using System.Web.UI.HtmlControls;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using OneLogin.Saml;

public partial class _Default : System.Web.UI.Page 
{
    protected void Page_Load(object sender, EventArgs e)
    {
        // replace with an instance of the users account.
        AccountSettings accountSettings = new AccountSettings();
        
        using (OneLogin.Saml.Response samlResponse = new Response(accountSettings))
        {
            samlResponse.LoadXmlFromBase64(Request.Form["SAMLResponse"]);

            if (samlResponse.IsValid())
            {
                Response.Write("OK!");
                Response.Write(samlResponse.GetNameID());
            }
            else
            {
                Response.Write("Failed");
            }
        }
    }
}
