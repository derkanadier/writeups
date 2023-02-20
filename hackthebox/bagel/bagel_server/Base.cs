// Decompiled with JetBrains decompiler
// Type: bagel_server.Base
// Assembly: bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 32A79BD4-65AA-4B36-9047-7C4DE45C43FB

using System;


#nullable enable
namespace bagel_server
{
  public class Base : Orders
  {
    private int userid = 0;
    private string session = "Unauthorized";

    public int UserId
    {
      get => this.userid;
      set => this.userid = value;
    }

    public string Session
    {
      get => this.session;
      set => this.session = value;
    }

    public string Time => DateTime.Now.ToString("h:mm:ss");
  }
}
