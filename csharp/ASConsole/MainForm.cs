using System;
using System.Data;
using System.Text;
using System.Drawing;
using System.ComponentModel;
using System.Collections.Generic;
using System.Windows.Forms;
using ASCrypt.Padding;
using ASCrypt;

namespace ASConsole
{
    public class MainForm : Form
    {
        private System.Windows.Forms.RichTextBox outputBox;
        private System.ComponentModel.IContainer components = null;

        public MainForm()
        {
            this.InitializeComponent();
            this.TestAllAlgorithms();
        }

        #region Windows Form Designer Generated Code

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.outputBox = new System.Windows.Forms.RichTextBox();
            this.SuspendLayout();
            // 
            // outputBox
            // 
            this.outputBox.BackColor = System.Drawing.Color.White;
            this.outputBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.outputBox.Font = new System.Drawing.Font("Courier New", 11, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Pixel, ((byte)(0)));
            this.outputBox.Location = new System.Drawing.Point(0, 0);
            this.outputBox.Name = "outputBox";
            this.outputBox.ReadOnly = true;
            this.outputBox.Size = new System.Drawing.Size(705, 461);
            this.outputBox.TabIndex = 0;
            this.outputBox.Text = "";
            this.outputBox.WordWrap = false;
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(705, 461);
            this.Controls.Add(this.outputBox);
            this.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.Name = "MainForm";
            this.Text = "ASCrypt Console";
            this.ResumeLayout(false);

        }

        #endregion

        #region Crypto Testing Methods

        /// <summary>
        /// Computes and shows the crypto results.
        /// </summary>
        private void TestAllAlgorithms()
        {
            /**
            * Input length is 17 chars but 19 bytes.
            */
            String input = "Hello to € World!";

            /**
            * Arrays for padding testing.
            */
            Byte[] pb = new Byte[12] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
            Byte[] nb = new Byte[12] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

            /**
            * Test PKCS#7 padding.
            */
            Byte[] pp = PKCS7.Pad(pb, 8);
			Byte[] pu = PKCS7.Unpad(pp);
            //
            this.outputBox.Text += "PKCS#7 padded: " + BytesToString(pp) + "\n";
            this.outputBox.Text += "PKCS#7 unpadded: " + BytesToString(pu) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test zero byte padding.
            */
			Byte[] np = ZEROS.Pad(nb, 8);
            Byte[] nu = ZEROS.Unpad(np);
            //
            this.outputBox.Text += "Zero byte padded: " + BytesToString(np) + "\n";
            this.outputBox.Text += "Zero byte unpadded: " + BytesToString(nu) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Text to bytes conversion from input.
            */
            Byte[] utf8Bytes = Encoding.UTF8.GetBytes(input);
            Byte[] ubeBytes = Encoding.BigEndianUnicode.GetBytes(input);
            Byte[] uleBytes = Encoding.Unicode.GetBytes(input);
            //
            this.outputBox.Text += "UTF-16 BE bytes: " + BytesToString(ubeBytes) + "\n";
            this.outputBox.Text += "UTF-16 LE bytes: " + BytesToString(uleBytes) + "\n";
            this.outputBox.Text += "UTF-8 bytes: " + BytesToString(utf8Bytes) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test base16 encoding.
            */
            String b16e = Base16.Encode(utf8Bytes);
            Byte[] b16d = Base16.Decode(b16e);
            //
            this.outputBox.Text += "Base16 encoded in UTF-8: " + b16e + "\n";
            this.outputBox.Text += "Base16 decoded in UTF-8: " + Encoding.UTF8.GetString(b16d) + "\n";
            this.outputBox.Text += "\n";
           
            /**
            * Test base64 encoding.
            */
            String b64e = Base64.Encode(utf8Bytes);
            Byte[] b64d = Base64.Decode(b64e);
            //
            this.outputBox.Text += "Base64 encoded in UTF-8: " + b64e + "\n";
            this.outputBox.Text += "Base64 decoded in UTF-8: " + Encoding.UTF8.GetString(b64d) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test generating GUID's.
            */
            String guid1 = GUID.Create();
            String guid2 = GUID.Create();
            String guid3 = GUID.Create();
            //
            this.outputBox.Text += "Generated GUID 1: " + guid1 + "\n";
            this.outputBox.Text += "Generated GUID 2: " + guid2 + "\n";
            this.outputBox.Text += "Generated GUID 3: " + guid3 + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test ROT13 encoding.
            */
            Byte[] r13e = ROT13.Encode(utf8Bytes);
            Byte[] r13d = ROT13.Decode(r13e);
            //
            this.outputBox.Text += "ROT13 encrypted in UTF-8: " + Encoding.UTF8.GetString(r13e) + "\n";
            this.outputBox.Text += "ROT13 decrypted in UTF-8: " + Encoding.UTF8.GetString(r13d) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test MD5 with one official test vector and custom input.
            * Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
            */
            Byte[] md5tv = MD5.Compute(new Byte[0]);
            Byte[] md5utf8 = MD5.Compute(utf8Bytes);
            Byte[] md5key = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] md5hmac = MD5.ComputeHMAC(md5key, utf8Bytes);
            //
            this.outputBox.Text += "MD5 from otv is ok: " + (Base16.Encode(md5tv) == "d41d8cd98f00b204e9800998ecf8427e").ToString() + "\n";
            this.outputBox.Text += "MD5 HMAC in UTF-8: " + Base16.Encode(md5hmac) + "\n";
            this.outputBox.Text += "MD5 in UTF-8: " + Base16.Encode(md5utf8) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test RIPEMD-160 with one official test vector and custom input.
            * Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
            */
            Byte[] rmd160tv = RMD160.Compute(new Byte[0]);
            Byte[] rmd160utf8 = RMD160.Compute(utf8Bytes);
            Byte[] rmd160key = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] rmd160hmac = RMD160.ComputeHMAC(rmd160key, utf8Bytes);
            //
            this.outputBox.Text += "RIPEMD-160 from otv is ok: " + (Base16.Encode(rmd160tv) == "9c1185a5c5e9fc54612808977ee8f548b2258d31").ToString() + "\n";
            this.outputBox.Text += "RIPEMD-160 HMAC in UTF-8: " + Base16.Encode(rmd160hmac) + "\n";
            this.outputBox.Text += "RIPEMD-160 in UTF-8: " + Base16.Encode(rmd160utf8) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test SHA-1 with one official test vector and custom input.
            * Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
            */
            Byte[] sha1tv = SHA1.Compute(new Byte[0]);
            Byte[] sha1utf8 = SHA1.Compute(utf8Bytes);
            Byte[] sha1key = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] sha1hmac = SHA1.ComputeHMAC(sha1key, utf8Bytes);
            //
            this.outputBox.Text += "SHA-1 from otv is ok: " + (Base16.Encode(sha1tv) == "da39a3ee5e6b4b0d3255bfef95601890afd80709").ToString() + "\n";
            this.outputBox.Text += "SHA-1 HMAC in UTF-8: " + Base16.Encode(sha1hmac) + "\n";
            this.outputBox.Text += "SHA-1 in UTF-8: " + Base16.Encode(sha1utf8) + "\n";
            this.outputBox.Text += "\n";

            /**
            * Test SHA-256 with one official test vector and custom input.
            * Vectors from: http://www.febooti.com/products/filetweak/members/hash-and-crc/test-vectors/
            */
            Byte[] sha256tv = SHA256.Compute(new Byte[0]);
            Byte[] sha256utf8 = SHA256.Compute(utf8Bytes);
            Byte[] sha256key = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] sha256hmac = SHA256.ComputeHMAC(sha256key, utf8Bytes);
            //
            this.outputBox.Text += "SHA-256 from otv is ok: " + (Base16.Encode(sha256tv) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").ToString() + "\n";
            this.outputBox.Text += "SHA-256 HMAC in UTF-8: " + Base16.Encode(sha256hmac) + "\n";
            this.outputBox.Text += "SHA-256 in UTF-8: " + Base16.Encode(sha256utf8) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test ARC4 with one official test vector and custom input.
            * Vectors from: http://reikon.us/arc4
            */
            Byte[] arc4tvk = Base16.Decode("0123456789abcdef");
			Byte[] arc4tvt = Base16.Decode("0123456789abcdef");
			Byte[] arc4tve = ARC4.Encrypt(arc4tvk, arc4tvt);
            Byte[] arc4tvd = ARC4.Decrypt(arc4tvk, arc4tve);
            //
            Byte[] arc4k = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] arc4e = ARC4.Encrypt(arc4k, utf8Bytes);
            Byte[] arc4d = ARC4.Decrypt(arc4k, arc4e);
            //
            this.outputBox.Text += "ARC4 otv encrypted is ok: " + (Base16.Encode(arc4tve) == "75b7878099e0c596") + "\n";
            this.outputBox.Text += "ARC4 otv decrypted is ok: " + (Base16.Encode(arc4tvd) == "0123456789abcdef") + "\n";
            this.outputBox.Text += "ARC4 encrypted in UTF-8: " + Base16.Encode(arc4e) + "\n";
            this.outputBox.Text += "ARC4 decrypted in UTF-8: " + Encoding.UTF8.GetString(arc4d) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test XXTEA with one official test vector and custom input.
            * Vectors from: http://www.crypt.co.za/post/27
            */
            Byte[] xxttvk = Base16.Decode("9e3779b99b9773e9b979379e6b695156");
            Byte[] xxttvt = Base16.Decode("0102040810204080fffefcf8f0e0c080");
            Byte[] xxttve = XXTEA.Encrypt(xxttvk, xxttvt);
            Byte[] xxttvd = XXTEA.Decrypt(xxttvk, xxttve);
            //
            Byte[] xxteak = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] xxteae = XXTEA.Encrypt(xxteak, PKCS7.Pad(utf8Bytes, 4));
            Byte[] xxtead = PKCS7.Unpad(XXTEA.Decrypt(xxteak, xxteae));
            //
            this.outputBox.Text += "XXTEA otv encrypted is ok: " + (Base16.Encode(xxttve) == "01b815fd2e4894d13555da434c9d868a") + "\n";
            this.outputBox.Text += "XXTEA otv decrypted is ok: " + (Base16.Encode(xxttvd) == "0102040810204080fffefcf8f0e0c080") + "\n";
            this.outputBox.Text += "XXTEA encrypted in UTF-8: " + Base16.Encode(xxteae) + "\n";
            this.outputBox.Text += "XXTEA decrypted in UTF-8: " + Encoding.UTF8.GetString(xxtead) + "\n";
            this.outputBox.Text += "\n";

            /**
            * Test AES-128 with one official test vector and custom input.
            * Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
            */
            Byte[] aes128tvk = new Byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            Byte[] aes128tvt = new Byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            Byte[] aes128tve = AES.Encrypt(aes128tvk, aes128tvt, OperationMode.ECB, null); // No padding needed.
            Byte[] aes128tvd = AES.Decrypt(aes128tvk, aes128tve, OperationMode.ECB, null); // No padding needed.
            //
            Byte[] aes128k = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] aes128e = AES.Encrypt(aes128k, PKCS7.Pad(utf8Bytes, 16), OperationMode.ECB, null);
            Byte[] aes128d = PKCS7.Unpad(AES.Decrypt(aes128k, aes128e, OperationMode.ECB, null));
            //
            this.outputBox.Text += "AES-128 otv encrypted is ok: " + (Base16.Encode(aes128tve) == "69c4e0d86a7b0430d8cdb78070b4c55a") + "\n";
            this.outputBox.Text += "AES-128 otv decrypted is ok: " + (Base16.Encode(aes128tvd) == "00112233445566778899aabbccddeeff") + "\n";
            this.outputBox.Text += "AES-128 (ECB mode) encrypted in UTF-8: " + Base16.Encode(aes128e) + "\n";
            this.outputBox.Text += "AES-128 (ECB mode) decrypted in UTF-8: " + Encoding.UTF8.GetString(aes128d) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test AES-192 with one official test vector and custom input.
            * Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
            */
            Byte[] aes192tvk = new Byte[24] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
            Byte[] aes192tvt = new Byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            Byte[] aes192tve = AES.Encrypt(aes192tvk, aes192tvt, OperationMode.ECB, null); // No padding needed.
            Byte[] aes192tvd = AES.Decrypt(aes192tvk, aes192tve, OperationMode.ECB, null); // No padding needed.
            //
            Byte[] aes192i = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] aes192k = Encoding.UTF8.GetBytes("123456789012345678901234");
            Byte[] aes192e = AES.Encrypt(aes192k, PKCS7.Pad(utf8Bytes, 16), OperationMode.CBC, aes192i);
            Byte[] aes192d = PKCS7.Unpad(AES.Decrypt(aes192k, aes192e, OperationMode.CBC, aes192i));
            //
            this.outputBox.Text += "AES-192 otv encrypted is ok: " + (Base16.Encode(aes192tve) == "dda97ca4864cdfe06eaf70a0ec0d7191") + "\n";
            this.outputBox.Text += "AES-192 otv decrypted is ok: " + (Base16.Encode(aes192tvd) == "00112233445566778899aabbccddeeff") + "\n";
            this.outputBox.Text += "AES-192 (CBC mode) encrypted in UTF-8: " + Base16.Encode(aes192e) + "\n";
            this.outputBox.Text += "AES-192 (CBC mode) decrypted in UTF-8: " + Encoding.UTF8.GetString(aes192d) + "\n";
            this.outputBox.Text += "\n";
            
            /**
            * Test AES-256 with one official test vector and custom input.
            * Vectors from: http://www.csrc.nist.gov/publications/fips/fips197/fips-197.pdf
            */
            Byte[] aes256tvk = new Byte[32] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
            Byte[] aes256tvt = new Byte[16] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
            Byte[] aes256tve = AES.Encrypt(aes256tvk, aes256tvt, OperationMode.ECB, null); // No padding needed.
            Byte[] aes256tvd = AES.Decrypt(aes256tvk, aes256tve, OperationMode.ECB, null); // No padding needed.
            //
            Byte[] aes256i = Encoding.UTF8.GetBytes("1234567890123456");
            Byte[] aes256k = Encoding.UTF8.GetBytes("12345678901234561234567890123456");
            Byte[] aes256e = AES.Encrypt(aes256k, PKCS7.Pad(utf8Bytes, 16), OperationMode.CBC, aes256i);
            Byte[] aes256d = PKCS7.Unpad(AES.Decrypt(aes256k, aes256e, OperationMode.CBC, aes256i));
            //
            this.outputBox.Text += "AES-256 otv encrypted is ok: " + (Base16.Encode(aes256tve) == "8ea2b7ca516745bfeafc49904b496089") + "\n";
            this.outputBox.Text += "AES-256 otv decrypted is ok: " + (Base16.Encode(aes256tvd) == "00112233445566778899aabbccddeeff") + "\n";
            this.outputBox.Text += "AES-256 (CBC mode) encrypted in UTF-8: " + Base16.Encode(aes256e) + "\n";
            this.outputBox.Text += "AES-256 (CBC mode) decrypted in UTF-8: " + Encoding.UTF8.GetString(aes256d) + "\n";
            this.outputBox.Text += "\n";
        }

        /// <summary>
        /// Converts a byte array to a ActionScript type array string.
        /// </summary>
        private String BytesToString(Byte[] bytes)
        {
            String text = "";
            for (Int32 i = 0; i < bytes.Length; i++)
            {
                if (i == bytes.Length - 1) text += bytes[i].ToString();
                else text += bytes[i].ToString() + ",";
            }
            return text;
        }

        #endregion

    }

}