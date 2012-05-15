using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Rhino;
using Rhino.Commands;

[CommandStyle(Style.ScriptRunner)]
public abstract class RhinoScriptCommand : Command
{
  /// <summary>
  /// Return the command's manifest resource name in the form of
  /// "solution.filename.extension"
  /// </summary>
  public abstract string ResourceName { get; }

  /// <summary>
  /// Return the command's decryption password here
  /// </summary>
  public abstract string Password { get; }

  /// <summary>
  /// Commmand.RunCommand override
  /// </summary>
  protected override Rhino.Commands.Result RunCommand(RhinoDoc doc, RunMode mode)
  {
    Rhino.Commands.Result rc = Rhino.Commands.Result.Success;

    if (!_bIsLoaded)
    {
      string script = ScriptFromResources(ResourceName, Password);
      if (!string.IsNullOrEmpty(script))
      {
        string macro = string.Format("_-RunScript ({0})", script);
        if (RhinoApp.RunScript(macro, false))
          _bIsLoaded = true;
        else
          rc = Result.Failure;
      }
    }

    if (rc == Result.Success)
    {
      string macro = string.Format("_-RunScript ({0})", EnglishName);
      RhinoApp.RunScript(macro, false);
    }

    return rc;
  }

  /// <summary>
  /// Returns a script that was embedded in the assembly's resources.
  /// </summary>
  private string ScriptFromResources(string resourceName, string password)
  {
    if (string.IsNullOrEmpty(resourceName) || string.IsNullOrEmpty(password))
      return null;

    string script = null;

    Assembly assembly = Assembly.GetExecutingAssembly();
    if (null != assembly)
    {
      string encryptedText = null;
      using (Stream stream = assembly.GetManifestResourceStream(resourceName))
      {
        try
        {
          using (StreamReader reader = new StreamReader(stream))
            encryptedText = reader.ReadToEnd();
        }
        catch
        {
        }
      }

      if (!string.IsNullOrEmpty(encryptedText))
        script = Decrypt(encryptedText, password);
    }

    return script;
  }

  /// <summary>
  /// Decrypts a string previously encrypted with RhinoScriptEncrypter.
  /// </summary>
  private string Decrypt(string encryptedText, string password)
  {
    if (string.IsNullOrEmpty(encryptedText) || string.IsNullOrEmpty(password))
      return null;

    string text = null;

    try
    {
      byte[] encryptedBuffer = Convert.FromBase64String(encryptedText);
      byte[] buffer = Decrypt(encryptedBuffer, password);
      text = System.Text.Encoding.Unicode.GetString(buffer);
    }

    catch
    {
      text = null;
    }

    return text;
  }

  /// <summary>
  /// Decrypts a byte array previously encrypted with RhinoScriptEncrypter.
  /// </summary>
  private byte[] Decrypt(byte[] encryptedBuffer, string password)
  {
    if (null == encryptedBuffer || 0 == encryptedBuffer.Length || string.IsNullOrEmpty(password))
      return null;

    byte[] buffer = null;
    CryptoStream cryptoStream = null;

    try
    {
      Rfc2898DeriveBytes secretKey = new Rfc2898DeriveBytes(password, _keySalt);
      RijndaelManaged cipher = new RijndaelManaged();
      ICryptoTransform transform = cipher.CreateDecryptor(secretKey.GetBytes(32), secretKey.GetBytes(16));
      MemoryStream memoryStream = new MemoryStream();
      cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write);
      cryptoStream.Write(encryptedBuffer, 0, encryptedBuffer.Length);
      cryptoStream.FlushFinalBlock();
      buffer = memoryStream.ToArray();
    }

    catch
    {
      buffer = null;
    }

    finally
    {
      if (null != cryptoStream)
        cryptoStream.Close();
    }

    return buffer;
  }

  private byte[] _keySalt = new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 };
  private bool _bIsLoaded = false;
}
