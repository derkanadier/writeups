// Decompiled with JetBrains decompiler
// Type: bagel_server.Orders
// Assembly: bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 32A79BD4-65AA-4B36-9047-7C4DE45C43FB

using System.Diagnostics;


#nullable enable
namespace bagel_server
{
  public class Orders
  {
    private string order_filename;
    private string order_info;
    private File file = new File();

    [field: DebuggerBrowsable]
    public object RemoveOrder { get; set; }

    public string WriteOrder
    {
      get => this.file.WriteFile;
      set
      {
        this.order_info = value;
        this.file.WriteFile = this.order_info;
      }
    }

    public string ReadOrder
    {
      get => this.file.ReadFile;
      set
      {
        this.order_filename = value;
        this.order_filename = this.order_filename.Replace("/", "");
        this.order_filename = this.order_filename.Replace("..", "");
        this.file.ReadFile = this.order_filename;
      }
    }
  }
}
