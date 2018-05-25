using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using GostCryptography.Cryptography;

namespace GostCryptography.Tests
{
	static class TestCertificates
	{
		/// <summary>
		/// Имя хранилища для поиска тестового сертификата.
		/// </summary>
		/// <remarks>
		/// Значение равно <see cref="StoreName.My"/>.
		/// </remarks>
		public const StoreName CertStoreName = StoreName.My;

        /// <summary>
        /// Местоположение для поиска тестового сертификата.
        /// </summary>
        /// <remarks>
        /// Значение равно <see cref="StoreLocation.LocalMachine"/>.
        /// </remarks>
        public const StoreLocation CertStoreLocation = StoreLocation.CurrentUser;//.LocalMachine;

		/// <summary>
		/// Сертификат ГОСТ Р 34.10-2001 с закрытым ключем.
		/// </summary>
		private static readonly X509Certificate2 GostCetificate = FindGostCertificate();


		/// <summary>
		/// Возвращает тестовый контейнер ключей ГОСТ.
		/// </summary>
		/// <remarks>
		/// Для простоты берется контейнер ключей сертификата, однако можно явно указать контейнер, например так:
		/// <code>
		/// var keyContainer1 = new CspParameters(ProviderTypes.VipNet, null, "MyVipNetContainer");
		/// var keyContainer2 = new CspParameters(ProviderTypes.CryptoPro, null, "MyCryptoProContainer");
		/// </code>
		/// </remarks>
		public static CspParameters GetKeyContainer()
		{
            var keyContainer2 = new CspParameters(ProviderTypes.CryptoPro, null, "MyCryptoProContainer");
            return GostCetificate.GetPrivateKeyInfo();
		}

		/// <summary>
		/// Возвращает тестовый сертификат ГОСТ с закрытым ключем.
		/// </summary>
		public static X509Certificate2 GetCertificate()
		{
			return GostCetificate;
		}


		private static X509Certificate2 FindGostCertificate()
		{
            // Для тестирования берется первый найденный сертификат ГОСТ с закрытым ключем.
            /*
            var cert = new X509Certificate2("Gost2001.pfx", "123");
            if (cert.HasPrivateKey && cert.SignatureAlgorithm.Value == "1.2.643.2.2.3") // old value 1.2.643.7.1.1.3.2 
            {
                return cert;
            }
            */
            
            var store = new X509Store(CertStoreName, CertStoreLocation);
			store.Open(OpenFlags.ReadOnly);
            int i = 0;
			try
			{
                foreach (var certificate in store.Certificates)
                {
                    if (certificate.HasPrivateKey && certificate.SignatureAlgorithm.Value == "1.2.643.2.2.3")
					{
                       //var temp = certificate.PrivateKey;
                      // if (i==1)
						return certificate;
                       // i++;
					}
				}
			}
			finally
			{
				store.Close();
			}
            
			return null;
		}
	}
}