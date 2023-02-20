// Decompiled with JetBrains decompiler
// Type: bagel_server.Bagel
// Assembly: bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 32A79BD4-65AA-4B36-9047-7C4DE45C43FB

using System;
using System.Text;
using System.Threading;
using WatsonWebsocket;


#nullable enable
namespace bagel_server
{
  public class Bagel
  {
    private static string _ServerIp = "*";
    private static int _ServerPort = 5000;
    private static bool _Ssl = false;
    private static WatsonWsServer _Server = (WatsonWsServer) null;

    private static void Main(string[] args)
    {
      Bagel.InitializeServer();
      Bagel.StartServer();
      while (true)
        Thread.Sleep(1000);
    }

    private static void InitializeServer()
    {
      Bagel._Server = new WatsonWsServer(Bagel._ServerIp, Bagel._ServerPort, Bagel._Ssl);
      Bagel._Server.AcceptInvalidCertificates = true;
      Bagel._Server.MessageReceived += new EventHandler<MessageReceivedEventArgs>(Bagel.MessageReceived);
    }

    private static async void StartServer() => await Bagel._Server.StartAsync(new CancellationToken());

    private static void MessageReceived(object sender, MessageReceivedEventArgs args)
    {
      string json = "";
      ArraySegment<byte> data;
      int num;
      if (args.Data != ArraySegment<byte>.op_Implicit((byte[]) null))
      {
        data = args.Data;
        num = data.Count > 0 ? 1 : 0;
      }
      else
        num = 0;
      if (num != 0)
      {
        Encoding utF8 = Encoding.UTF8;
        data = args.Data;
        byte[] array = data.Array;
        data = args.Data;
        int count = data.Count;
        json = utF8.GetString(array, 0, count);
      }
      Handler handler = new Handler();
      object obj1 = handler.Deserialize(json);
      object obj2 = handler.Serialize(obj1);
      Bagel._Server.SendAsync(args.IpPort, obj2.ToString(), new CancellationToken());
    }
  }
}
