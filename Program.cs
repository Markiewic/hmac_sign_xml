using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace hmac_sign
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                RSACryptoServiceProvider Key = new RSACryptoServiceProvider();
                
                CreateSomeXml("Example.xml");
                Console.WriteLine("XML-документ создан.");

                byte[] hmacKey = new byte[64];
                new RNGCryptoServiceProvider().GetBytes(hmacKey);
                
                SignXmlFile("Example.xml", "SignedExample.xml", Key, hmacKey);
                Console.WriteLine("XML-документ подписан.");

                Console.WriteLine("Проверка подписи...");
                bool result = VerifyXmlFile("SignedExample.xml", hmacKey);
                
                if (result)
                {
                    Console.WriteLine("Подпись XML-документа валидна.");
                }
                else
                {
                    Console.WriteLine("Подпись XML-документа невалидна.");
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine(e.Message);
            }
        }
        public static void SignXmlFile(string FileName, string SignedFileName, RSA Key, byte[] hmacKey)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = false;
            doc.Load(new XmlTextReader(FileName));

            SignedXml signedXml = new SignedXml(doc);
            signedXml.SigningKey = Key;
            signedXml.SignedInfo.SignatureMethod = SignedXml.XmlDsigHMACSHA1Url;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

            XmlDsigExcC14NTransform canMethod = (XmlDsigExcC14NTransform)signedXml.SignedInfo.CanonicalizationMethodObject;
            canMethod.InclusiveNamespacesPrefixList = "Sign";

            Reference reference = new Reference();
            reference.Uri = "";
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);
            signedXml.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new RSAKeyValue((RSA)Key));
            signedXml.KeyInfo = keyInfo;

            signedXml.ComputeSignature(new HMACSHA1(hmacKey));

            XmlElement xmlDigitalSignature = signedXml.GetXml();
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }
            XmlTextWriter xmltw = new XmlTextWriter(SignedFileName, new UTF8Encoding(false));
            doc.WriteTo(xmltw);
            xmltw.Close();
        }

        public static Boolean VerifyXmlFile(String Name, byte[] hmacKey)
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            xmlDocument.Load(Name);

            SignedXml signedXml = new SignedXml(xmlDocument);
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName("Signature");
            signedXml.LoadXml((XmlElement)nodeList[0]);

            return signedXml.CheckSignature(new HMACSHA1(hmacKey));
        }

        public static void CreateSomeXml(string FileName)
        {
            XmlDocument document = new XmlDocument();
            XmlNode node = document.CreateNode(XmlNodeType.Element, "", "MyXML", "Don't_Sign");
            document.AppendChild(node);
            XmlNode subnode = document.CreateNode(XmlNodeType.Element, "", "TempElement", "Sign");
            subnode.InnerText = "Here is some data to sign.";
            document.DocumentElement.AppendChild(subnode);

            XmlTextWriter xmltw = new XmlTextWriter(FileName, new UTF8Encoding(false));
            document.WriteTo(xmltw);
            xmltw.Close();
        }
    }
}