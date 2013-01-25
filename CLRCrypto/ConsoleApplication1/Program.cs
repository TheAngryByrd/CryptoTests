﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            RijndaelManaged r = new RijndaelManaged();
            ulong uStep = 4001;
            ulong uRounds = 0;
            byte[] pbIV = new byte[16];

            byte[] pbKey = new byte[32];
            byte[] pbNewKey = new byte[32];
            for (int i = 0; i < pbKey.Length; ++i)
            {
                pbKey[i] = (byte)i;
                pbNewKey[i] = (byte)i;
            }

            r.IV = pbIV;
            r.Mode = CipherMode.ECB;
            r.KeySize = 256;
            r.Key = pbKey;
            ICryptoTransform iCrypt = r.CreateEncryptor();

            DateTime dtStart = DateTime.Now;
            TimeSpan ts;

            double dblReqMillis = 1000;
            while (true)
            {
                for (ulong j = 0; j < uStep; ++j)
                {
                    iCrypt.TransformBlock(pbNewKey, 0, 16, pbNewKey, 0);
                    iCrypt.TransformBlock(pbNewKey, 16, 16, pbNewKey, 16);
                }

                uRounds += uStep;
                if (uRounds < uStep) // Overflow check
                {
                    uRounds = ulong.MaxValue;
                    break;
                }

                ts = DateTime.Now - dtStart;
                if (ts.TotalMilliseconds > dblReqMillis) break;
            }

            Console.WriteLine("CLR Rounds Completed: " + uRounds.ToString());
            Console.ReadLine();
        }
    }
}
