// Decompiled with JetBrains decompiler
// Type: bagel_server.DB
// Assembly: bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 32A79BD4-65AA-4B36-9047-7C4DE45C43FB

using Microsoft.Data.SqlClient;
using System;

namespace bagel_server
{
  public class DB
  {
    [Obsolete("The production team has to decide where the database server will be hosted. This method is not fully implemented.")]
    public void DB_connection()
    {
      SqlConnection sqlConnection = new SqlConnection("Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K");
    }
  }
}
