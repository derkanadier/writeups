// Decompiled with JetBrains decompiler
// Type: bagel_server.Handler
// Assembly: bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 32A79BD4-65AA-4B36-9047-7C4DE45C43FB

using Newtonsoft.Json;


#nullable enable
namespace bagel_server
{
  public class Handler
  {
    public object Serialize(object obj) => (object) JsonConvert.SerializeObject(obj, (Formatting) 1, new JsonSerializerSettings()
    {
      TypeNameHandling = (TypeNameHandling) 4
    });

    public object Deserialize(string json)
    {
      try
      {
        return (object) JsonConvert.DeserializeObject<Base>(json, new JsonSerializerSettings()
        {
          TypeNameHandling = (TypeNameHandling) 4
        });
      }
      catch
      {
        return (object) "{\"Message\":\"unknown\"}";
      }
    }
  }
}
