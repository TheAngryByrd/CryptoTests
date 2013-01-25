using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestPlatform.UnitTestFramework;
using Windows.Security.Cryptography.Core;
using Windows.Security.Cryptography;
using System.Diagnostics;

namespace WinRTCrypto
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
            byte[] pbIV = new byte[16];
            byte[] pbKey = new byte[32];
            byte[] pbNewKey = new byte[32];

            for (int i = 0; i < pbKey.Length; ++i)
            {
                pbKey[i] = (byte)i;
                pbNewKey[i] = (byte)i;
            }

            var pbKeyBuffer = CryptographicBuffer.CreateFromByteArray(pbKey);
            var pbNewKeyBuffer = CryptographicBuffer.CreateFromByteArray(pbNewKey);

            SymmetricKeyAlgorithmProvider symKeyProvider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesEcb);
            var transFormKey = symKeyProvider.CreateSymmetricKey(pbKeyBuffer);

            DateTime dtStart = DateTime.Now;
            TimeSpan ts;
            ulong uRounds = 0;
            double dblReqMillis = 1000;
            while (true)
            {

                pbNewKeyBuffer = CryptographicEngine.Encrypt(transFormKey, pbNewKeyBuffer, null);


                uRounds++;
                ts = DateTime.Now - dtStart;
                if (ts.TotalMilliseconds > dblReqMillis) break;
            }

            Debug.WriteLine("WinRT Rounds Completed: " + uRounds.ToString());

        }
    }
}
