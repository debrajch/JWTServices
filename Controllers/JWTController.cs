using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace JWTServices.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class JWTController : ControllerBase
    {
       
        [HttpGet]
        public string GetJWTToken(string userId, string password)
        {
            var token = GetToken(false, userId, password, false);
            return token;
        }

        [HttpGet]
        public string GetEncryptedJWTTokenWithCertificate(string userId, string password)
        {
            var token = GetToken(true, userId, password, true); ;
            return token;

        }
        [HttpGet]
        public string GetEncryptedJWTTokenWithEncryptionKey(string userId, string password)
        {
            var token = GetToken(true, userId, password,false); ;
            return token;
        }

        [HttpGet]
        public string DecodeToken(string jwt_token)
        {
            var handler1 = new JwtSecurityTokenHandler();
            var tokenRead = handler1.ReadJwtToken(jwt_token);
            var name = tokenRead.Claims.Where(x => x.Type == "userId").FirstOrDefault().Value.ToString();
            return name;
            //xxxxx
            //https://www.scottbrady91.com/C-Sharp/JSON-Web-Encryption-JWE-in-dotnet-Core
        }


        /// <summary>
        /// Token Generator
        /// </summary>
        /// <param name="isTokenTobeEncrypted"></param>
        /// <param name="userId"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private string GetToken(bool isTokenTobeEncrypted, string userId, string password,
            bool useCertificate )
        {
            bool authenticated = ValidateUser( userId,  password);
            JwtSecurityToken token; 
            var issuer = "debraj.com";  //normally this will be your site URL    

            ///signing stuff
            string signkeySecret = "my_sign_key1234777715156156157237"; //will be used by the decoding app    
            var signKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signkeySecret));
            var signingCredentials = new SigningCredentials(signKey, SecurityAlgorithms.HmacSha256);

            //Claims stuff
            var myClaims = new List<Claim>();
            myClaims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            myClaims.Add(new Claim("userId", userId));
            myClaims.Add(new Claim("authenticated", "1"));
            myClaims.Add(new Claim("name", "debraj chakraboty"));

            //handler 
            var handler = new JwtSecurityTokenHandler();
            //Create Security Token object by giving required parameters  
            if (isTokenTobeEncrypted)
            {             
                if (!useCertificate)
                {
                    //encryption stuff 
                    string encryptionKeySecretTemp = "my_encryption_key64613856365204126401152875"; //will be used by the decoding app 
                    var encryptionKeySecretTempEncoded = Encoding.UTF8.GetBytes(encryptionKeySecretTemp);
                    // Note that the ecKey should have 256 / 8 length:
                    byte[] encryptionKeySecretEncoded = new byte[256 / 8];
                    Array.Copy(encryptionKeySecretTempEncoded, encryptionKeySecretEncoded, 256 / 8);
                    var encryptionKey = new SymmetricSecurityKey(encryptionKeySecretEncoded);
                    var encryptionCredentials = new EncryptingCredentials(encryptionKey,
                       SecurityAlgorithms.Aes256KW, SecurityAlgorithms.Aes256CbcHmacSha512);
                    token = handler.CreateJwtSecurityToken(issuer, issuer,
                   new ClaimsIdentity(myClaims), DateTime.Now, DateTime.Now.AddDays(1), DateTime.Now,
                   signingCredentials, encryptionCredentials);
                }
                else
                {
                    X509Certificate2 certificate = new X509Certificate2();
                    X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.ReadOnly);
                    if (store.Certificates.Count > 0)
                    {
                        certificate = store.Certificates[0];
                    }
                    var encryptionCredentials = new
                    X509EncryptingCredentials(certificate);
                    token = handler.CreateJwtSecurityToken(issuer, issuer,
                   new ClaimsIdentity(myClaims), DateTime.Now, DateTime.Now.AddDays(1), DateTime.Now,
                   signingCredentials, encryptionCredentials);
                }                        
            }
            else
            {
                token = handler.CreateJwtSecurityToken(issuer, issuer,
                   new ClaimsIdentity(myClaims), DateTime.Now, DateTime.Now.AddDays(1), DateTime.Now,
                   signingCredentials, null);
            }
            var jwt_token = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt_token;
        }

        /// <summary>
        /// Custom Authenication 
        /// </summary>
        /// <param name="userId"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        private bool ValidateUser(string userId, string password)
        {
            return true;// put ur logic here
        }
    }
}
