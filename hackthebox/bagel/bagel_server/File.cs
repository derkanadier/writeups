// Decompiled with JetBrains decompiler
// Type: bagel_server.File
// Assembly: bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 32A79BD4-65AA-4B36-9047-7C4DE45C43FB

using System;
using System.IO;
using System.Text;


#nullable enable
namespace bagel_server
{
  public class File
  {
    private string file_content;
    private string IsSuccess = (string) null;
    private string directory = "/opt/bagel/orders/";
    private string filename = "orders.txt";

    public string ReadFile
    {
      set
      {
        this.filename = value;
        this.ReadContent(this.directory + this.filename);
      }
      get => this.file_content;
    }

    public void ReadContent(string path)
    {
      try
      {
        this.file_content += string.Join("\n", File.ReadLines(path, Encoding.UTF8));
      }
      catch (Exception ex)
      {
        this.file_content = "Order not found!";
      }
    }

    public string WriteFile
    {
      get => this.IsSuccess;
      set => this.WriteContent(this.directory + this.filename, value);
    }

    public void WriteContent(string filename, string line)
    {
      try
      {
        File.WriteAllText(filename, line);
        this.IsSuccess = "Operation successed";
      }
      catch (Exception ex)
      {
        this.IsSuccess = "Operation failed";
      }
    }
  }
}
