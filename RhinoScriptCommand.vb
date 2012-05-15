Imports System
Imports System.IO
Imports System.Security
Imports System.Security.Cryptography
Imports System.Reflection
Imports System.Runtime.InteropServices
Imports System.Text
Imports Rhino
Imports Rhino.Commands

Public MustInherit Class RhinoScriptCommand
  Inherits Rhino.Commands.Command

  ''' <summary>
  ''' Return the command's manifest resource name in the form of
  ''' "solution.filename.extension"
  ''' </summary>
  Public MustOverride ReadOnly Property ResourceName As String

  ''' <summary>
  ''' Return the command's decryption password here
  ''' </summary>
  Public MustOverride ReadOnly Property Password As String

  ''' <summary>
  ''' Decrypts a string previously encrypted with RhinoScriptEncrypter.
  ''' </summary>
  ''' <param name="encryptedText"></param>
  Private Function Decrypt(encryptedText As String, password As String) As String
    If String.IsNullOrEmpty(encryptedText) OrElse String.IsNullOrEmpty(password) Then
      Return Nothing
    End If

    Dim text As String = Nothing

    Try
      Dim encryptedBuffer As Byte() = Convert.FromBase64String(encryptedText)
      Dim buffer As Byte() = Decrypt(encryptedBuffer, password)
      text = System.Text.Encoding.Unicode.GetString(buffer)

    Catch
      text = Nothing
    End Try

    Return text
  End Function

  ''' <summary>
  ''' Commmand.RunCommand override
  ''' </summary>
  Protected Overrides Function RunCommand(doc As RhinoDoc, mode As RunMode) As Rhino.Commands.Result
    Dim rc As Rhino.Commands.Result = Rhino.Commands.Result.Success

    If Not _bIsLoaded Then
      Dim script As String = ScriptFromResources(ResourceName, Password)
      If Not String.IsNullOrEmpty(script) Then
        Dim macro As String = String.Format("_-RunScript ({0})", script)
        If RhinoApp.RunScript(macro, False) Then
          _bIsLoaded = True
        Else
          rc = Result.Failure
        End If
      End If
    End If

    If rc = Result.Success Then
      Dim macro As String = String.Format("_-RunScript ({0})", EnglishName)
      RhinoApp.RunScript(macro, False)
    End If

    Return rc
  End Function

  ''' <summary>
  ''' Returns a script that was embedded in the assembly's resources.
  ''' </summary>
  Private Function ScriptFromResources(resourceName As String, password As String) As String
    If String.IsNullOrEmpty(resourceName) OrElse String.IsNullOrEmpty(password) Then
      Return Nothing
    End If

    Dim script As String = Nothing

    Dim pluginAssembly As Assembly = Assembly.GetExecutingAssembly()
    If pluginAssembly IsNot Nothing Then
      Dim encryptedText As String = Nothing
      Using stream As Stream = pluginAssembly.GetManifestResourceStream(resourceName)
        Try
          Using reader As New StreamReader(stream)
            encryptedText = reader.ReadToEnd()
          End Using
        Catch
        End Try
      End Using

      If Not String.IsNullOrEmpty(encryptedText) Then
        script = Decrypt(encryptedText, password)
      End If
    End If

    Return script
  End Function

  ''' <summary>
  ''' Decrypts a byte array previously encrypted with RhinoScriptEncrypter.
  ''' </summary>
  Private Function Decrypt(encryptedBuffer As Byte(), password As String) As Byte()
    If encryptedBuffer Is Nothing OrElse 0 = encryptedBuffer.Length OrElse String.IsNullOrEmpty(password) Then
      Return Nothing
    End If

    Dim buffer As Byte() = Nothing
    Dim cryptoStream As CryptoStream = Nothing

    Try
      Dim secretKey As New Rfc2898DeriveBytes(password, _keySalt)
      Dim cipher As New RijndaelManaged()
      Dim transform As ICryptoTransform = cipher.CreateDecryptor(secretKey.GetBytes(32), secretKey.GetBytes(16))
      Dim memoryStream As New MemoryStream()
      cryptoStream = New CryptoStream(memoryStream, transform, CryptoStreamMode.Write)
      cryptoStream.Write(encryptedBuffer, 0, encryptedBuffer.Length)
      cryptoStream.FlushFinalBlock()
      buffer = memoryStream.ToArray()

    Catch
      buffer = Nothing
    Finally

      If cryptoStream IsNot Nothing Then
        cryptoStream.Close()
      End If
    End Try

    Return buffer
  End Function

  ''' <summary>
  ''' Private members
  ''' </summary>
  Private _keySalt As Byte() = New Byte() {&H49, &H76, &H61, &H6E, &H20, &H4D, &H65, &H64, &H76, &H65, &H64, &H65, &H76}
  Private _bIsLoaded As Boolean = False

End Class
