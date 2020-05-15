package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/process"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func convert(info interface{}){
	var test map[string]interface{}
	data,err:=json.MarshalIndent(info,"","")
	if(err!=nil){
		fmt.Println("Error:",err)
	}
	json.Unmarshal([]byte(data),&test)
	for keys,values:=range test{
		fmt.Println(keys,":",values)
	}
}


func local(){
	fmt.Println("\nHost information:")
	info,err:=host.Info()
	if(err!=nil){
		fmt.Println("Error:",err)
	}
	convert(info)

	fmt.Println("\nCpu information:")
	cpuinfo,err:=cpu.Info()
	if(err!=nil){
		fmt.Println("Error:",err)
	}
	for key,value:=range cpuinfo{
		_=key
		convert(value)

	}
	fmt.Println("\nDisk information:")
	datadisk,err:=disk.Partitions(true)
	if err!=nil{
		fmt.Println("Error:",err)
	}
	for key,value:=range datadisk{
		_=key
		convert(value)

	}


}

func GbkToUtf8(s []byte) ([]byte, error) {
	reader := transform.NewReader(bytes.NewReader(s), simplifiedchinese.GBK.NewDecoder())
	d, e := ioutil.ReadAll(reader)
	if e != nil {
		return nil, e
	}
	return d, nil
}

func command(data string) ([]byte) {
	if strings.Contains(data,"wmic"){
		data_s:=strings.Split(strings.TrimSpace(strings.ReplaceAll(data,"wmic",""))," ")
		cmd := exec.Command("wmic.exe", data_s...)
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			jg, err := GbkToUtf8(out)
			if err != nil {
				fmt.Println(err)
			} else {
				return jg
			}
		}

	}else {
		data:=strings.Split(strings.TrimSpace(data)," ")
		cmd := exec.Command("cmd.exe", data...)
		out, err := cmd.Output()
		if err != nil {
			fmt.Println("Error:", err)
		} else {
			jg, err := GbkToUtf8(out)
			if err != nil {
				fmt.Println(err)
			} else {
				return jg
			}
		}
	}
	return nil
}

func userinfo(){
	fmt.Printf("Login ID:%s",command("/c whoami /LOGONID"))
	hostname:=command("/c hostname")
	fmt.Printf("Hostname:%s",hostname)
	r,_:=regexp.Compile("S-.*")
	sid:=r.Find([]byte(command("/c whoami /user")))
	fmt.Printf("User id:%s\n",sid)
	fmt.Println("Current Groups:")
	fmt.Printf("%s\n",command("/c whoami /groups"))
	fmt.Println("Users of the corresponding process:")
	fmt.Printf("%s",command("/c tasklist /v"))
	fmt.Printf("\n");
}

func processinfo(){
	fmt.Println("\nToken information:")
	p,_:=process.Pids()
	for number,pid:=range p{
		_=number
		pidinfo,_:=process.GetWin32Proc(pid)
		for _,infos:=range pidinfo{
			convert(infos)
		}
		fmt.Println("\n")
	}
}

func exists(path string)(bool){
	_,err:=os.Stat(path)
	if err!=nil{
		if os.IsExist(err){
			return true
		}else{
			return false
		}
	}
	return true
}

func services(){
	if exists("C:\\Windows\\System32\\wbem\\wmic.exe")==true{
		fmt.Println("wmic.exe exists")
		fmt.Println("Get Service:")
		fmt.Printf("%s",command("wmic service where started=true get name, startname"))
	}else{
		fmt.Println("Not found wmic.exe")
		fmt.Println("Get Service:")
		fmt.Printf("%s",command("/c powershell Get-Service"))
	}

	fmt.Println("\nLocalSystem Services:")
	servicename:=strings.Split(strings.ReplaceAll(string(command("/c powershell IEX(\"get-service | Select-Object Name\")")),"\n","----"),"----")
	for calc:=0;calc<len(servicename);calc++{
		if calc>1 {
			sname:=strings.TrimSpace(servicename[calc])
			if sname!=""{
				cmds:=fmt.Sprintf("/c powershell sc.exe qc \"%s\"",sname)
				datas:=string(command(cmds))
				if strings.Contains(datas,"LocalSystem")==true{
						fmt.Println(datas)
				}
			}
		}
	}

	fmt.Println("\nService path without double quotes:")
	for calc:=0;calc<len(servicename);calc++{
		if calc>1 {
			sname:=strings.TrimSpace(servicename[calc])
			if sname!=""{
				cmds:=fmt.Sprintf("/c powershell sc.exe qc \"%s\"",sname)
				datas:=command(cmds)
				r:=regexp.MustCompile(`BINARY_PATH_NAME.*`)
				zz:=r.FindAll(datas,-1)
				if len(zz)>0{
					if strings.Contains(string(zz[0]),"\"")==false{
						fmt.Println(string(datas))
					}
				}
			}
		}
	}

	fmt.Println("\nService weak folder permissions:")
	for calc:=0;calc<len(servicename);calc++{
		if calc>1 {
			sname:=strings.TrimSpace(servicename[calc])
			if sname!=""{
				cmds:=fmt.Sprintf("/c powershell sc.exe qc \"%s\"",sname)
				datas:=command(cmds)
				r:=regexp.MustCompile(`BINARY_PATH_NAME.*`)
				r2:=regexp.MustCompile("SERVICE_NAME: .*")
				zz:=r.FindAll(datas,-1)
				sername:=r2.FindAll(datas,-1)
				if len(zz)>0 {
					re := regexp.MustCompile("[A-Z][:].*exe")
					path := re.FindAll(zz[0], -1)
					if len(path) > 0 {
						paths := strings.Split(string(path[0]), "\\")
						pathx := strings.Join(paths[0:len(paths)-1], "\\")
						pathname := fmt.Sprintf("%s\\test.txt", pathx)
						_, err := os.Create(pathname)
						if err == nil {
							os.Remove(pathname)
							fmt.Println(pathx, string(sername[0]))
						}
					}
				}
			}
		}
	}

	fmt.Println("\nService weak permission check:")
	for calc:=0;calc<len(servicename);calc++ {
		if calc > 1 {
			sname := strings.TrimSpace(servicename[calc])
			if sname != "" {
				regpath:=fmt.Sprintf("SYSTEM\\CurrentControlSet\\services\\%s",sname)
				key,err:=registry.OpenKey(registry.LOCAL_MACHINE,regpath,registry.ALL_ACCESS)
				if err==nil{
					_=key
					fmt.Println(sname)
				}
			}
		}
	}

}

func registryhandle(key registry.Key,path string,authority uint32)(registry.Key){
	key,err:=registry.OpenKey(key,path,authority)
	if(err!=nil){
		fmt.Println("Error:",err)
	}
	return key
}

func registryinfo(){
	fmt.Println("AlwaysInstallElevated Policy Query,Reference link:https://bbs.mayidui.net/t2253-1.html")
	key:=registryhandle(registry.CURRENT_USER,"Software\\Policies\\Microsoft\\Windows\\Installer",registry.QUERY_VALUE)
	value,_,err:=key.GetIntegerValue("AlwaysInstallElevated")
	if err!=nil{
		fmt.Println("Error:",err)
	}
	if value==1{
		fmt.Println("AlwaysInstallElevated status:On")
	}else{
		fmt.Println("AlwaysInstallElevated status:Off")
	}

	fmt.Println("\nLas protection check:")
	key=registryhandle(registry.LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\LSA",registry.QUERY_VALUE)
	lsa,_,err:=key.GetIntegerValue("RunAsPPL")
	if err!=nil{
		fmt.Println("Lsa protection:Off")
	}else if lsa==1{
		fmt.Println("Lsa protection:On")
	}

	fmt.Println("\nwdigest protection check:")
	key=registryhandle(registry.LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",registry.QUERY_VALUE)
	wdigest,_,err:=key.GetIntegerValue("UseLogonCredential")
	if err!=nil{
		fmt.Println("Wdigest protection:Off")
	}else if wdigest!=1{
		fmt.Println("Wdigest protection:On")
	}

	usastatus:=make(map[string]uint64)
	level:=make(map[string]interface{})
	key=registryhandle(registry.LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",registry.QUERY_VALUE)
	ConsentPromptBehaviorAdmin,_,err:=key.GetIntegerValue("ConsentPromptBehaviorAdmin")
	EnableLUA,_,err:=key.GetIntegerValue("EnableLUA")
	PromptOnSecureDesktop,_,err:=key.GetIntegerValue("PromptOnSecureDesktop")
	usastatus["ConsentPromptBehaviorAdmin"]=ConsentPromptBehaviorAdmin
	usastatus["EnableLUA"]=EnableLUA
	usastatus["PromptOnSecureDesktop"]=PromptOnSecureDesktop

	if(usastatus["ConsentPromptBehaviorAdmin"]==2&&usastatus["EnableLUA"]==1&&usastatus["PromptOnSecureDesktop"]==1){
		level["level"]="hight"
	}else if(usastatus["ConsentPromptBehaviorAdmin"]==5&&usastatus["EnableLUA"]==1&&usastatus["PromptOnSecureDesktop"]==1){
		level["level"]="intermediate"
	}else if(usastatus["ConsentPromptBehaviorAdmin"]==5&&usastatus["EnableLUA"]==1&&usastatus["PromptOnSecureDesktop"]==0){
		level["level"]="low"
	}else if(usastatus["ConsentPromptBehaviorAdmin"]==0&&usastatus["EnableLUA"]==0&&usastatus["PromptOnSecureDesktop"]==0){
		level["level"]="off"
	}else{
		level["level"]="unknown"
	}
	fmt.Println("\nUAC level:",level["level"])

}

func internetinfo(){
	fmt.Println("\nip information:")
	fmt.Printf("%s",command("/c ipconfig /all"))
	fmt.Println("Internet connection:")
	net:=command("/c netstat -ano")
	fmt.Printf("%s",net)
	fmt.Println("\nLocal connection information:")
	re:=regexp.MustCompile(".*127.0.0.1.*")
	for _,data:=range re.FindAll(net,-1){
		fmt.Println(string(data))
	}
}

func patchinfo(){
	fmt.Println("patch query:")
	fmt.Println("Patch query help link:https://bugs.hacking8.com/tiquan/")
	fmt.Println("exploit:https://github.com/SecWiki/windows-kernel-exploits")
	fmt.Printf("%s",command("/c powershell IEX(\"Get-HotFix | Select-Object HotFixID\")"))
}

func usage(){
	var banner=`---------------------------------------
|Supporting tools for power withdrawal|
|--------------------------------------
|Author:Jiushi|	アクセシビリティツール|
---------------------------------------`
	fmt.Println(banner)
	fmt.Println("Example:powerhight [-u]")
}

func avexists()  {
	data:=map[string]string{"360TRAY": "360安全卫士-实时保护", "360SAFE": "360安全卫士-主程序", "ZHUDONGFANGYU": "360安全卫士-主动防御", "360SD": "360杀毒", "A2GUARD": "a-squared杀毒", "AD-WATCH": "Lavasoft杀毒", "CLEANER8": "The Cleaner杀毒", "VBA32LDER": "vb32杀毒", "MONGOOSAGUI": "Mongoosa杀毒", "CORANTICONTROLCENTER32": "Coranti2012杀毒", "F-PROT": "F-Prot AntiVirus", "CMCTRAYICON": "CMC杀毒", "K7TSECURITY": "K7杀毒", "UNTHREAT": "UnThreat杀毒", "CKSOFTSHIEDANTIVIRUS4": "Shield Antivirus杀毒", "AVWATCHSERVICE": "VIRUSfighter杀毒", "ARCATASKSSERVICE": "ArcaVir杀毒", "IPTRAY": "Immunet杀毒", "PSAFESYSTRAY": "PSafe杀毒", "NSPUPSVC": "nProtect杀毒", "SPYWARETERMINATORSHIELD": "SpywareTerminator杀毒", "BKAVSERVICE": "Bkav杀毒", "MSMPENG": "Microsoft Security Essentials", "SBAMSVC": "VIPRE", "CCSVCHST": "Norton杀毒", "F-SECURE": "冰岛", "AVP": "Kaspersky", "KVMONXP": "江民杀毒", "RAVMOND": "瑞星杀毒", "MCSHIELD": "Mcafee", "TBMON": "Mcafee", "FRAMEWORKSERVICE": "Mcafee", "EGUI": "ESET NOD32", "EKRN": "ESET NOD32", "EGUIPROXY": "ESET NOD32", "KXETRAY": "金山毒霸", "KNSDTRAY": "可牛杀毒", "TMBMSRV": "趋势杀毒", "AVCENTER": "Avira(小红伞)", "AVGUARD": "Avira(小红伞)", "AVGNT": "Avira(小红伞)", "SCHED": "Avira(小红伞)", "ASHDISP": "Avast网络安全", "RTVSCAN": "诺顿杀毒", "CCAPP": "Symantec Norton", "NPFMNTOR": "Norton杀毒软件相关进程", "CCSETMGR": "赛门铁克", "CCREGVFY": "Norton杀毒软件自身完整性检查程序", "VPTRAY": "Norton病毒防火墙-盾牌图标程序", "KSAFE": "金山卫士", "QQPCRTP": "QQ电脑管家", "MINER": "流量矿石", "AYAGENT": "韩国胶囊", "PATRAY": "安博士", "V3SVC": "安博士V3", "AVGWDSVC": "AVG杀毒", "QUHLPSVC": "QUICK HEAL杀毒", "MSSECESS": "微软杀毒", "SAVPROGRESS": "Sophos杀毒", "SOPHOSUI": "Sophos杀毒", "SOPHOSFS": "Sophos杀毒", "SOPHOSHEALTH": "Sophos杀毒", "SOPHOSSAFESTORE64": "Sophos杀毒", "SOPHOSCLEANM": "Sophos杀毒", "FSAVGUI": "F-Secure杀毒", "VSSERV": "比特梵德", "REMUPD": "熊猫卫士", "FORTITRAY": "飞塔", "SAFEDOG": "安全狗", "PARMOR": "木马克星", "IPARMOR": "木马克星", "BEIKESAN": "贝壳云安全", "KSWEBSHIELD": "金山网盾", "TROJANHUNTER": "木马猎手", "GG": "巨盾网游安全盾", "ADAM": "绿鹰安全精灵", "AST": "超级巡警", "ANANWIDGET": "墨者安全专家", "AVK": "GData", "AVG": "AVG Anti-Virus", "SPIDERNT": "Dr.web", "AVGAURD": "Avira Antivir", "VSMON": "ZoneAlarm", "CPF": "Comodo", "OUTPOST": "Outpost Firewall", "RFWMAIN": "瑞星防火墙", "KPFWTRAY": "金山网镖", "FYFIREWALL": "风云防火墙", "MPMON": "微点主动防御", "PFW": "天网防火墙", "S": "在抓鸡", "1433": "在扫1433", "DUB": "在爆破", "SERVUDAEMON": "发现S-U", "BAIDUSDSVC": "百度杀毒-服务进程", "BAIDUSDTRAY": "百度杀毒-托盘进程", "BAIDUSD": "百度杀毒-主程序", "SAFEDOGGUARDCENTER": "安全狗", "SAFEDOGUPDATECENTER": "安全狗", "SAFEDOGSITEIIS": "安全狗", "SAFEDOGTRAY": "安全狗", "SAFEDOGSERVERUI": "安全狗", "D_SAFE_MANAGE": "D盾", "D_MANAGE": "D盾", "YUNSUO_AGENT_SERVICE": "云锁", "YUNSUO_AGENT_DAEMON": "云锁", "HWSPANEL": "护卫神", "HWS_UI": "护卫神", "HWS": "护卫神", "HWSD": "护卫神", "HIPSTRAY": "火绒", "WSCTRL": "火绒", "USYSDIAG": "火绒", "WEBSCANX": "网络病毒克星", "SPHINX": "SPHINX防火墙", "BDDOWNLOADER": "百度卫士", "BAIDUANSVX": "百度卫士-主进程", "AVASTUI": "Avast!5主程序", "EMET_AGENT": "EMET", "EMET_SERVICE": "EMET", "FIRESVC": "McAfee", "FIRETRAY": "McAfee", "HIPSVC": "McAfee", "MFEVTPS": "McAfee", "MCAFEEFIRE": "McAfee", "SCAN32": "McAfee", "SHSTAT": "McAfee", "VSTSKMGR": "McAfee", "ENGINESERVER": "McAfee", "MFEANN": "McAfee", "MCSCRIPT": "McAfee", "UPDATERUI": "McAfee", "UDATERUI": "McAfee", "NAPRDMGR": "McAfee", "CLEANUP": "McAfee", "CMDAGENT": "McAfee", "FRMINST": "McAfee", "MCSCRIPT_INUSE": "McAfee", "MCTRAY": "McAfee", "AAWTRAY": "已知杀软进程,名称暂未收录", "AD-AWARE": "已知杀软进程,名称暂未收录", "MSASCUI": "已知杀软进程,名称暂未收录", "_AVP32": "卡巴斯基", "_AVPCC": "卡巴斯基", "_AVPM": "卡巴斯基", "AAVGAPI": "AVG", "ACKWIN32": "已知杀软进程,名称暂未收录", "ADAWARE": "已知杀软进程,名称暂未收录", "ADVXDWIN": "已知杀软进程,名称暂未收录", "AGENTSVR": "已知杀软进程,名称暂未收录", "AGENTW": "已知杀软进程,名称暂未收录", "ALERTSVC": "Norton AntiVirus", "ALEVIR": "已知杀软进程,名称暂未收录", "ALOGSERV": "McAfee VirusScan", "AMON9X": "已知杀软进程,名称暂未收录", "ANTI-TROJAN": "Anti-Trojan Elite", "ANTIVIRUS": "已知杀软进程,名称暂未收录", "ANTS": "已知杀软进程,名称暂未收录", "APIMONITOR": "已知杀软进程,名称暂未收录", "APLICA32": "已知杀软进程,名称暂未收录", "APVXDWIN": "熊猫卫士", "ARR": "Application Request Route", "ATCON": "已知杀软进程,名称暂未收录", "ATGUARD": "AntiVir", "ATRO55EN": "已知杀软进程,名称暂未收录", "ATUPDATER": "已知杀软进程,名称暂未收录", "ATWATCH": "Mustek", "AU": "NSIS", "AUPDATE": "Symantec", "AUTO-PROTECT.NAV80TRY": "已知杀软进程,名称暂未收录", "AUTODOWN": "AntiVirus AutoUpdater", "AUTOTRACE": "已知杀软进程,名称暂未收录", "AUTOUPDATE": "已知杀软进程,名称暂未收录", "AVCONSOL": "McAfee", "AVE32": "已知杀软进程,名称暂未收录", "AVGCC32": "AVG", "AVGCTRL": "AVG", "AVGEMC": "AVG", "AVGRSX": "AVG", "AVGSERV": "AVG", "AVGSERV9": "AVG", "AVGW": "AVG", "AVKPOP": "G DATA SOFTWARE AG", "AVKSERV": "已知杀软进程,名称暂未收录", "AVKSERVICE": "已知杀软进程,名称暂未收录", "AVKWCTL9": "G DATA SOFTWARE AG", "AVLTMAIN": "Panda Software Aplication", "AVNT": "H+BEDV Datentechnik GmbH", "AVP32": "已知杀软进程,名称暂未收录", "AVPCC": "Kaspersky", "AVPDOS32": " Kaspersky AntiVirus", "AVPM": "Kaspersky", "AVPTC32": " Kaspersky AntiVirus", "AVPUPD": " Kaspersky AntiVirus", "AVSCHED32": "H+BEDV", "AVSYNMGR": "McAfee", "AVWIN": " H+BEDV", "AVWIN95": "已知杀软进程,名称暂未收录", "AVWINNT": "已知杀软进程,名称暂未收录", "AVWUPD": "已知杀软进程,名称暂未收录", "AVWUPD32": "已知杀软进程,名称暂未收录", "AVWUPSRV": "H+BEDV", "AVXMONITOR9X": "已知杀软进程,名称暂未收录", "AVXMONITORNT": "已知杀软进程,名称暂未收录", "AVXQUAR": "已知杀软进程,名称暂未收录", "BACKWEB": "已知杀软进程,名称暂未收录", "BARGAINS": "Exact Advertising SpyWare", "BD_PROFESSIONAL": "已知杀软进程,名称暂未收录", "BEAGLE": "Avast", "BELT": "已知杀软进程,名称暂未收录", "BIDEF": "已知杀软进程,名称暂未收录", "BIDSERVER": "已知杀软进程,名称暂未收录", "BIPCP": "已知杀软进程,名称暂未收录", "BIPCPEVALSETUP": "已知杀软进程,名称暂未收录", "BISP": "已知杀软进程,名称暂未收录", "BLACKD": "BlackICE", "BLACKICE": "已知杀软进程,名称暂未收录", "BLINK": "micromedia", "BLSS": "CBlaster", "BOOTCONF": "已知杀软进程,名称暂未收录", "BOOTWARN": "Symantec", "BORG2": "已知杀软进程,名称暂未收录", "BPC": "Grokster", "BRASIL": "Exact Advertising", "BS120": "已知杀软进程,名称暂未收录", "BUNDLE": "已知杀软进程,名称暂未收录", "BVT": "已知杀软进程,名称暂未收录", "CCEVTMGR": "Symantec", "CCPXYSVC": "已知杀软进程,名称暂未收录", "CDP": "CyberLink Corp.", "CFD": "Motive Communications", "CFGWIZ": " Norton AntiVirus", "CFIADMIN": "已知杀软进程,名称暂未收录", "CFIAUDIT": "已知杀软进程,名称暂未收录", "CFINET": "已知杀软进程,名称暂未收录", "CFINET32": "已知杀软进程,名称暂未收录", "CLAW95": "已知杀软进程,名称暂未收录", "CLAW95CF": "已知杀软进程,名称暂未收录", "CLEAN": "windows流氓软件清理大师", "CLEANER": "windows流氓软件清理大师", "CLEANER3": "windows流氓软件清理大师", "CLEANPC": "windows流氓软件清理大师", "CLICK": "已知杀软进程,名称暂未收录", "CMESYS": "已知杀软进程,名称暂未收录", "CMGRDIAN": "已知杀软进程,名称暂未收录", "CMON016": "已知杀软进程,名称暂未收录", "CONNECTIONMONITOR": "已知杀软进程,名称暂未收录", "CPD": "McAfee", "CPF9X206": "已知杀软进程,名称暂未收录", "CPFNT206": "已知杀软进程,名称暂未收录", "CTRL": "已知杀软进程,名称暂未收录", "CV": "已知杀软进程,名称暂未收录", "CWNB181": "已知杀软进程,名称暂未收录", "CWNTDWMO": "已知杀软进程,名称暂未收录", "DATEMANAGER": "已知杀软进程,名称暂未收录", "DCOMX": "已知杀软进程,名称暂未收录", "DEFALERT": "Symantec", "DEFSCANGUI": "Symantec", "DEFWATCH": "Norton Antivirus", "DEPUTY": "已知杀软进程,名称暂未收录", "DIVX": "已知杀软进程,名称暂未收录", "DLLCACHE": "已知杀软进程,名称暂未收录", "DLLREG": "已知杀软进程,名称暂未收录", "DOORS": "已知杀软进程,名称暂未收录", "DPF": "已知杀软进程,名称暂未收录", "DPFSETUP": "已知杀软进程,名称暂未收录", "DPPS2": "PanicWare", "DRWATSON": "已知杀软进程,名称暂未收录", "DRWEB32": "已知杀软进程,名称暂未收录", "DRWEBUPW": "已知杀软进程,名称暂未收录", "DSSAGENT": "Broderbund", "DVP95": "已知杀软进程,名称暂未收录", "DVP95_0": "已知杀软进程,名称暂未收录", "ECENGINE": "已知杀软进程,名称暂未收录", "EFPEADM": "已知杀软进程,名称暂未收录", "EMSW": "Alset Inc", "ENT": "已知杀软进程,名称暂未收录", "ESAFE": "已知杀软进程,名称暂未收录", "ESCANHNT": "已知杀软进程,名称暂未收录", "ESCANV95": "已知杀软进程,名称暂未收录", "ESPWATCH": "已知杀软进程,名称暂未收录", "ETHEREAL": "RationalClearCase", "ETRUSTCIPE": "已知杀软进程,名称暂未收录", "EVPN": "已知杀软进程,名称暂未收录", "EXANTIVIRUS-CNET": "已知杀软进程,名称暂未收录", "EXE.AVXW": "已知杀软进程,名称暂未收录", "EXPERT": "已知杀软进程,名称暂未收录", "EXPLORE": "已知杀软进程,名称暂未收录", "F-AGNT95": "已知杀软进程,名称暂未收录", "F-PROT95": "已知杀软进程,名称暂未收录", "F-STOPW": "已知杀软进程,名称暂未收录", "FAMEH32": "已知杀软进程,名称暂未收录", "FAST": " FastUsr", "FCH32": "F-Secure", "FIH32": "F-Secure", "FINDVIRU": "F-Secure", "FIREWALL": "AshampooSoftware", "FNRB32": "F-Secure", "FP-WIN": " F-Prot Antivirus OnDemand", "FP-WIN_TRIAL": "已知杀软进程,名称暂未收录", "FPROT": "已知杀软进程,名称暂未收录", "FRW": "已知杀软进程,名称暂未收录", "FSAA": "F-Secure", "FSAV": "F-Secure", "FSAV32": "F-Secure", "FSAV530STBYB": "F-Secure", "FSAV530WTBYB": "F-Secure", "FSAV95": "F-Secure", "FSGK32": "F-Secure", "FSM32": "F-Secure", "FSMA32": "F-Secure", "FSMB32": "F-Secure", "GATOR": "已知杀软进程,名称暂未收录", "GBMENU": "已知杀软进程,名称暂未收录", "GBPOLL": "已知杀软进程,名称暂未收录", "GENERICS": "已知杀软进程,名称暂未收录", "GMT": "已知杀软进程,名称暂未收录", "GUARD": "ewido", "GUARDDOG": "ewido", "HACKTRACERSETUP": "已知杀软进程,名称暂未收录", "HBINST": "已知杀软进程,名称暂未收录", "HBSRV": "已知杀软进程,名称暂未收录", "HOTACTIO": "已知杀软进程,名称暂未收录", "HOTPATCH": "已知杀软进程,名称暂未收录", "HTLOG": "已知杀软进程,名称暂未收录", "HTPATCH": "Silicon Integrated Systems Corporation", "HWPE": "已知杀软进程,名称暂未收录", "HXDL": "已知杀软进程,名称暂未收录", "HXIUL": "已知杀软进程,名称暂未收录", "IAMAPP": "Symantec", "IAMSERV": "已知杀软进程,名称暂未收录", "IAMSTATS": "Symantec", "IBMASN": "已知杀软进程,名称暂未收录", "IBMAVSP": "已知杀软进程,名称暂未收录", "ICLOAD95": "已知杀软进程,名称暂未收录", "ICLOADNT": "已知杀软进程,名称暂未收录", "ICMON": "已知杀软进程,名称暂未收录", "ICSUPP95": "已知杀软进程,名称暂未收录", "ICSUPPNT": "已知杀软进程,名称暂未收录", "IDLE": "已知杀软进程,名称暂未收录", "IEDLL": "已知杀软进程,名称暂未收录", "IEDRIVER": " Urlblaze.com", "IFACE": "Panda Antivirus Module", "IFW2000": "已知杀软进程,名称暂未收录", "INETLNFO": "已知杀软进程,名称暂未收录", "INFUS": "Infus Dialer", "INFWIN": "Msviewparasite", "INIT": "已知杀软进程,名称暂未收录", "INTDEL": "Inet Delivery", "INTREN": "已知杀软进程,名称暂未收录", "IOMON98": "已知杀软进程,名称暂未收录", "ISTSVC": "已知杀软进程,名称暂未收录", "JAMMER": "已知杀软进程,名称暂未收录", "JDBGMRG": "已知杀软进程,名称暂未收录", "JEDI": "已知杀软进程,名称暂未收录", "KAVLITE40ENG": "已知杀软进程,名称暂未收录", "KAVPERS40ENG": "已知杀软进程,名称暂未收录", "KAVPF": "Kaspersky", "KAZZA": "Kapersky", "KEENVALUE": "EUNIVERSE INC", "KERIO-PF-213-EN-WIN": "已知杀软进程,名称暂未收录", "KERIO-WRL-421-EN-WIN": "已知杀软进程,名称暂未收录", "KERIO-WRP-421-EN-WIN": "已知杀软进程,名称暂未收录", "KERNEL32": "已知杀软进程,名称暂未收录", "KILLPROCESSSETUP161": "已知杀软进程,名称暂未收录", "LAUNCHER": "Intercort Systems", "LDNETMON": "已知杀软进程,名称暂未收录", "LDPRO": "已知杀软进程,名称暂未收录", "LDPROMENU": "已知杀软进程,名称暂未收录", "LDSCAN": "Windows Trojans Inspector", "LNETINFO": "已知杀软进程,名称暂未收录", "LOADER": "已知杀软进程,名称暂未收录", "LOCALNET": "已知杀软进程,名称暂未收录", "LOCKDOWN": "已知杀软进程,名称暂未收录", "LOCKDOWN2000": "已知杀软进程,名称暂未收录", "LOOKOUT": "已知杀软进程,名称暂未收录", "LORDPE": "已知杀软进程,名称暂未收录", "LSETUP": "已知杀软进程,名称暂未收录", "LUALL": "Symantec", "LUAU": "Symantec", "LUCOMSERVER": "Norton", "LUINIT": "已知杀软进程,名称暂未收录", "LUSPT": "已知杀软进程,名称暂未收录", "MAPISVC32": "已知杀软进程,名称暂未收录", "MCAGENT": "McAfee", "MCMNHDLR": "McAfee", "MCTOOL": "McAfee", "MCUPDATE": "McAfee", "MCVSRTE": "McAfee", "MCVSSHLD": "McAfee", "MD": "已知杀软进程,名称暂未收录", "MFIN32": "MyFreeInternetUpdate", "MFW2EN": "MyFreeInternetUpdate", "MFWENG3.02D30": "MyFreeInternetUpdate", "MGAVRTCL": "McAfee", "MGAVRTE": "McAfee", "MGHTML": "McAfee", "MGUI": "BullGuard", "MINILOG": "Zone Alarm", "MMOD": "EzulaInc", "MONITOR": "已知杀软进程,名称暂未收录", "MOOLIVE": "已知杀软进程,名称暂未收录", "MOSTAT": "WurldMediaInc", "MPFAGENT": "McAfee", "MPFSERVICE": "McAfee", "MPFTRAY": "McAfee", "MRFLUX": "已知杀软进程,名称暂未收录", "MSAPP": "已知杀软进程,名称暂未收录", "MSBB": "已知杀软进程,名称暂未收录", "MSBLAST": "已知杀软进程,名称暂未收录", "MSCACHE": "Integrated Search Technologies Spyware", "MSCCN32": "已知杀软进程,名称暂未收录", "MSCMAN": "OdysseusMarketingInc", "MSCONFIG": "已知杀软进程,名称暂未收录", "MSDM": "已知杀软进程,名称暂未收录", "MSDOS": "已知杀软进程,名称暂未收录", "MSIEXEC16": "已知杀软进程,名称暂未收录", "MSINFO32": "已知杀软进程,名称暂未收录", "MSLAUGH": "已知杀软进程,名称暂未收录", "MSMGT": "Total Velocity Spyware", "MSMSGRI32": "已知杀软进程,名称暂未收录", "MSSMMC32": "已知杀软进程,名称暂未收录", "MSSYS": "已知杀软进程,名称暂未收录", "MSVXD": "W32/Datom-A", "MU0311AD": "已知杀软进程,名称暂未收录", "MWATCH": "已知杀软进程,名称暂未收录", "N32SCANW": "已知杀软进程,名称暂未收录", "NAV": "Reuters Limited", "NAVAP.NAVAPSVC": "已知杀软进程,名称暂未收录", "NAVAPSVC": "Norton", "NAVAPW32": "Norton", "NAVDX": "已知杀软进程,名称暂未收录", "NAVLU32": "Norton", "NAVNT": "已知杀软进程,名称暂未收录", "NAVSTUB": "已知杀软进程,名称暂未收录", "NAVW32": "Norton Antivirus", "NAVWNT": "已知杀软进程,名称暂未收录", "NC2000": "已知杀软进程,名称暂未收录", "NCINST4": "已知杀软进程,名称暂未收录", "NDD32": "诺顿磁盘医生", "NEOMONITOR": "已知杀软进程,名称暂未收录", "NEOWATCHLOG": "NeoWatch", "NETARMOR": "已知杀软进程,名称暂未收录", "NETD32": "已知杀软进程,名称暂未收录", "NETINFO": "已知杀软进程,名称暂未收录", "NETMON": "已知杀软进程,名称暂未收录", "NETSCANPRO": "已知杀软进程,名称暂未收录", "NETSPYHUNTER-1.2": "已知杀软进程,名称暂未收录", "NETSTAT": "已知杀软进程,名称暂未收录", "NETUTILS": "已知杀软进程,名称暂未收录", "NISSERV": "Norton", "NISUM": "Norton", "NMAIN": "Norton", "NOD32": "ESET NOD32", "NORMIST": "已知杀软进程,名称暂未收录", "NORTON_INTERNET_SECU_3.0_407": "已知杀软进程,名称暂未收录", "NOTSTART": "已知杀软进程,名称暂未收录", "NPF40_TW_98_NT_ME_2K": "已知杀软进程,名称暂未收录", "NPFMESSENGER": "已知杀软进程,名称暂未收录", "NPROTECT": "Symantec", "NPSCHECK": "Norton", "NPSSVC": "Norton", "NSCHED32": "已知杀软进程,名称暂未收录", "NSSYS32": "已知杀软进程,名称暂未收录", "NSTASK32": "已知杀软进程,名称暂未收录", "NSUPDATE": "已知杀软进程,名称暂未收录", "NT": "已知杀软进程,名称暂未收录", "NTRTSCAN": "趋势科技", "NTVDM": "已知杀软进程,名称暂未收录", "NTXCONFIG": "已知杀软进程,名称暂未收录", "NUI": "已知杀软进程,名称暂未收录", "NUPGRADE": "已知杀软进程,名称暂未收录", "NVARCH16": "已知杀软进程,名称暂未收录", "NVC95": "已知杀软进程,名称暂未收录", "NVSVC32": "已知杀软进程,名称暂未收录", "NWINST4": "已知杀软进程,名称暂未收录", "NWSERVICE": "已知杀软进程,名称暂未收录", "NWTOOL16": "已知杀软进程,名称暂未收录", "OLLYDBG": "已知杀软进程,名称暂未收录", "ONSRVR": "已知杀软进程,名称暂未收录", "OPTIMIZE": "已知杀软进程,名称暂未收录", "OSTRONET": "已知杀软进程,名称暂未收录", "OTFIX": "已知杀软进程,名称暂未收录", "OUTPOSTINSTALL": "Outpost", "OUTPOSTPROINSTALL": "已知杀软进程,名称暂未收录", "PADMIN": "已知杀软进程,名称暂未收录", "PANIXK": "已知杀软进程,名称暂未收录", "PATCH": "趋势科技", "PAVCL": "已知杀软进程,名称暂未收录", "PAVPROXY": "熊猫卫士", "PAVSCHED": "已知杀软进程,名称暂未收录", "PAVW": "已知杀软进程,名称暂未收录", "PCCWIN98": "已知杀软进程,名称暂未收录", "PCFWALLICON": "已知杀软进程,名称暂未收录", "PCIP10117_0": "已知杀软进程,名称暂未收录", "PCSCAN": "趋势科技", "PDSETUP": "已知杀软进程,名称暂未收录", "PERISCOPE": "已知杀软进程,名称暂未收录", "PERSFW": "Tiny Personal Firewall", "PERSWF": "已知杀软进程,名称暂未收录", "PF2": "已知杀软进程,名称暂未收录", "PFWADMIN": "已知杀软进程,名称暂未收录", "PGMONITR": "PromulGate SpyWare", "PINGSCAN": "已知杀软进程,名称暂未收录", "PLATIN": "已知杀软进程,名称暂未收录", "POP3TRAP": "PC-cillin", "POPROXY": "NortonAntiVirus", "POPSCAN": "已知杀软进程,名称暂未收录", "PORTDETECTIVE": "已知杀软进程,名称暂未收录", "PORTMONITOR": "已知杀软进程,名称暂未收录", "POWERSCAN": "Integrated Search Technologies", "PPINUPDT": "已知杀软进程,名称暂未收录", "PPTBC": "已知杀软进程,名称暂未收录", "PPVSTOP": "已知杀软进程,名称暂未收录", "PRIZESURFER": "Prizesurfer", "PRMT": "OpiStat", "PRMVR": "Adtomi", "PROCDUMP": "已知杀软进程,名称暂未收录", "PROCESSMONITOR": "Sysinternals", "PROCEXPLORERV1.0": "已知杀软进程,名称暂未收录", "PROGRAMAUDITOR": "已知杀软进程,名称暂未收录", "PROPORT": "已知杀软进程,名称暂未收录", "PROTECTX": "ProtectX", "PSPF": "已知杀软进程,名称暂未收录", "PURGE": "已知杀软进程,名称暂未收录", "QCONSOLE": "Norton AntiVirus Quarantine Console", "QSERVER": "Norton Internet Security", "RAPAPP": "BlackICE", "RAV7": "已知杀软进程,名称暂未收录", "RAV7WIN": "已知杀软进程,名称暂未收录", "RAV8WIN32ENG": "已知杀软进程,名称暂未收录", "RAY": "已知杀软进程,名称暂未收录", "RB32": "RapidBlaster", "RCSYNC": "PrizeSurfer", "REALMON": "Realmon ", "REGED": "已知杀软进程,名称暂未收录", "REGEDIT": "已知杀软进程,名称暂未收录", "REGEDT32": "已知杀软进程,名称暂未收录", "RESCUE": "已知杀软进程,名称暂未收录", "RESCUE32": "卡巴斯基互联网安全套装", "RRGUARD": "已知杀软进程,名称暂未收录", "RSHELL": "已知杀软进程,名称暂未收录", "RTVSCN95": "Real-time Virus Scanner", "RULAUNCH": "McAfee User Interface", "RUN32DLL": "PAL PC Spy", "RUNDLL": "已知杀软进程,名称暂未收录", "RUNDLL16": "已知杀软进程,名称暂未收录", "RUXDLL32": "已知杀软进程,名称暂未收录", "SAFEWEB": "PSafe Tecnologia", "SAHAGENTSCAN32": "已知杀软进程,名称暂未收录", "SAVE": "已知杀软进程,名称暂未收录", "SAVENOW": "已知杀软进程,名称暂未收录", "SBSERV": "Norton Antivirus", "SC": "已知杀软进程,名称暂未收录", "SCAM32": "已知杀软进程,名称暂未收录", "SCAN95": "已知杀软进程,名称暂未收录", "SCANPM": "已知杀软进程,名称暂未收录", "SCRSCAN": "360杀毒", "SERV95": "已知杀软进程,名称暂未收录", "SETUP_FLOWPROTECTOR_US": "已知杀软进程,名称暂未收录", "SETUPVAMEEVAL": "已知杀软进程,名称暂未收录", "SFC": "System file checker", "SGSSFW32": "已知杀软进程,名称暂未收录", "SH": "MKS Toolkit for Win3", "SHELLSPYINSTALL": "已知杀软进程,名称暂未收录", "SHN": "已知杀软进程,名称暂未收录", "SHOWBEHIND": "MicroSmarts Enterprise Component ", "SMC": "已知杀软进程,名称暂未收录", "SMS": "已知杀软进程,名称暂未收录", "SMSS32": "已知杀软进程,名称暂未收录", "SOAP": "System Soap Pro", "SOFI": "已知杀软进程,名称暂未收录", "SPERM": "已知杀软进程,名称暂未收录", "SPF": "已知杀软进程,名称暂未收录", "SPOLER": "已知杀软进程,名称暂未收录", "SPOOLCV": "已知杀软进程,名称暂未收录", "SPOOLSV32": "已知杀软进程,名称暂未收录", "SPYXX": "已知杀软进程,名称暂未收录", "SREXE": "已知杀软进程,名称暂未收录", "SRNG": "已知杀软进程,名称暂未收录", "SS3EDIT": "已知杀软进程,名称暂未收录", "SSG_4104": "已知杀软进程,名称暂未收录", "SSGRATE": "已知杀软进程,名称暂未收录", "ST2": "已知杀软进程,名称暂未收录", "START": "已知杀软进程,名称暂未收录", "STCLOADER": "已知杀软进程,名称暂未收录", "SUPFTRL": "已知杀软进程,名称暂未收录", "SUPPORT": "已知杀软进程,名称暂未收录", "SUPPORTER5": "eScorcher反病毒", "SVCHOSTC": "已知杀软进程,名称暂未收录", "SVCHOSTS": "已知杀软进程,名称暂未收录", "SWEEP95": "已知杀软进程,名称暂未收录", "SWEEPNET.SWEEPSRV.SYS.SWNETSUP": "已知杀软进程,名称暂未收录", "SYMPROXYSVC": "Symantec", "SYMTRAY": "Symantec", "SYSEDIT": "已知杀软进程,名称暂未收录", "SYSUPD": "已知杀软进程,名称暂未收录", "TASKMG": "已知杀软进程,名称暂未收录", "TASKMO": "已知杀软进程,名称暂未收录", "TAUMON": "已知杀软进程,名称暂未收录", "TBSCAN": "ThunderBYTE", "TC": "TimeCalende", "TCA": "已知杀软进程,名称暂未收录", "TCM": "已知杀软进程,名称暂未收录", "TDS-3": "已知杀软进程,名称暂未收录", "TDS2-98": "已知杀软进程,名称暂未收录", "TDS2-NT": "已知杀软进程,名称暂未收录", "TEEKIDS": "已知杀软进程,名称暂未收录", "TFAK": "已知杀软进程,名称暂未收录", "TFAK5": "已知杀软进程,名称暂未收录", "TGBOB": "已知杀软进程,名称暂未收录", "TITANIN": "TitanHide", "TITANINXP": "已知杀软进程,名称暂未收录", "TRACERT": "已知杀软进程,名称暂未收录", "TRICKLER": "已知杀软进程,名称暂未收录", "TRJSCAN": "已知杀软进程,名称暂未收录", "TRJSETUP": "已知杀软进程,名称暂未收录", "TROJANTRAP3": "已知杀软进程,名称暂未收录", "TSADBOT": "已知杀软进程,名称暂未收录", "TVMD": "Total Velocity", "TVTMD": " Total Velocity", "UNDOBOOT": "已知杀软进程,名称暂未收录", "UPDAT": "已知杀软进程,名称暂未收录", "UPDATE": "已知杀软进程,名称暂未收录", "UPGRAD": "已知杀软进程,名称暂未收录", "UTPOST": "已知杀软进程,名称暂未收录", "VBCMSERV": "已知杀软进程,名称暂未收录", "VBCONS": "已知杀软进程,名称暂未收录", "VBUST": "已知杀软进程,名称暂未收录", "VBWIN9X": "已知杀软进程,名称暂未收录", "VBWINNTW": "已知杀软进程,名称暂未收录", "VCSETUP": "已知杀软进程,名称暂未收录", "VET32": "已知杀软进程,名称暂未收录", "VET95": "已知杀软进程,名称暂未收录", "VETTRAY": "eTrust", "VFSETUP": "已知杀软进程,名称暂未收录", "VIR-HELP": "已知杀软进程,名称暂未收录", "VIRUSMDPERSONALFIREWALL": "已知杀软进程,名称暂未收录", "VNLAN300": "已知杀软进程,名称暂未收录", "VNPC3000": "已知杀软进程,名称暂未收录", "VPC32": "Symantec", "VPC42": "Symantec", "VPFW30S": "已知杀软进程,名称暂未收录", "VSCAN40": "已知杀软进程,名称暂未收录", "VSCENU6.02D30": "已知杀软进程,名称暂未收录", "VSCHED": "已知杀软进程,名称暂未收录", "VSECOMR": "已知杀软进程,名称暂未收录", "VSHWIN32": "McAfee", "VSISETUP": "已知杀软进程,名称暂未收录", "VSMAIN": "McAfee", "VSSTAT": "McAfee", "VSWIN9XE": "已知杀软进程,名称暂未收录", "VSWINNTSE": "已知杀软进程,名称暂未收录", "VSWINPERSE": "已知杀软进程,名称暂未收录", "W32DSM89": "已知杀软进程,名称暂未收录", "W9X": "已知杀软进程,名称暂未收录", "WATCHDOG": "已知杀软进程,名称暂未收录", "WEBDAV": "已知杀软进程,名称暂未收录", "WEBTRAP": "已知杀软进程,名称暂未收录", "WFINDV32": "已知杀软进程,名称暂未收录", "WHOSWATCHINGME": "已知杀软进程,名称暂未收录", "WIMMUN32": "已知杀软进程,名称暂未收录", "WIN-BUGSFIX": "已知杀软进程,名称暂未收录", "WIN32": "已知杀软进程,名称暂未收录", "WIN32US": "已知杀软进程,名称暂未收录", "WINACTIVE": "已知杀软进程,名称暂未收录", "WINDOW": "已知杀软进程,名称暂未收录", "WINDOWS": "已知杀软进程,名称暂未收录", "WININETD": "已知杀软进程,名称暂未收录", "WININITX": "已知杀软进程,名称暂未收录", "WINLOGIN": "已知杀软进程,名称暂未收录", "WINMAIN": "已知杀软进程,名称暂未收录", "WINNET": "已知杀软进程,名称暂未收录", "WINPPR32": "已知杀软进程,名称暂未收录", "WINRECON": "已知杀软进程,名称暂未收录", "WINSERVN": "已知杀软进程,名称暂未收录", "WINSSK32": "已知杀软进程,名称暂未收录", "WINSTART": "已知杀软进程,名称暂未收录", "WINSTART001": "已知杀软进程,名称暂未收录", "WINTSK32": "已知杀软进程,名称暂未收录", "WINUPDATE": "已知杀软进程,名称暂未收录", "WKUFIND": "已知杀软进程,名称暂未收录", "WNAD": "已知杀软进程,名称暂未收录", "WNT": "已知杀软进程,名称暂未收录", "WRADMIN": "已知杀软进程,名称暂未收录", "WRCTRL": "已知杀软进程,名称暂未收录", "WSBGATE": "已知杀软进程,名称暂未收录", "WUPDATER": "已知杀软进程,名称暂未收录", "WUPDT": "已知杀软进程,名称暂未收录", "WYVERNWORKSFIREWALL": "已知杀软进程,名称暂未收录", "XPF202EN": "已知杀软进程,名称暂未收录", "ZAPRO": "Zone Alarm", "ZAPSETUP3001": "已知杀软进程,名称暂未收录", "ZATUTOR": "已知杀软进程,名称暂未收录", "ZONALM2601": "已知杀软进程,名称暂未收录", "ZONEALARM": "Zone Alarm", "A2CMD": "Emsisoft Anti-Malware", "A2SERVICE": "a-squared free", "A2FREE": "a-squared Free", "ADVCHK": "Norton AntiVirus", "AGB": "安天防线", "AKRNL": "已知杀软进程,名称暂未收录", "AHPROCMONSERVER": "安天防线", "AIRDEFENSE": "AirDefense", "AVIRA": "小红伞杀毒", "AMON": "Tiny Personal Firewall", "TROJAN": "已知杀软进程,名称暂未收录", "AVZ": "AVZ", "ANTIVIR": "已知杀软进程,名称暂未收录", "ARMOR2NET": "已知杀软进程,名称暂未收录", "ASHEXE": "已知杀软进程,名称暂未收录", "ASHENHCD": "已知杀软进程,名称暂未收录", "ASHMAISV": "Alwil", "ASHPOPWZ": "已知杀软进程,名称暂未收录", "ASHSERV": "Avast Anti-virus", "ASHSIMPL": "AVAST!VirusCleaner", "ASHSKPCK": "已知杀软进程,名称暂未收录", "ASHWEBSV": "Avast", "ASWUPDSV": "Avast", "ASWSCAN": "Avast", "AVCIMAN": "熊猫卫士", "AVENGINE": "熊猫卫士", "AVESVC": "Avira AntiVir Security Service", "AVEVAL": "已知杀软进程,名称暂未收录", "AVEVL32": "已知杀软进程,名称暂未收录", "AVGAM": "AVG", "AVGCC": "AVG", "AVGCHSVX": "AVG", "AVGNSX": "AVG", "AVGFWSRV": "AVG", "AVGNTMGR": "AVG", "AVGTRAY": "AVG", "AVGUPSVC": "AVG", "AVINITNT": "Command AntiVirus for NT Server", "AVKWCTL": "已知杀软进程,名称暂未收录", "AVSERVER": "Kerio MailServer", "AVXMONITOR": "已知杀软进程,名称暂未收录", "BDSWITCH": "BitDefender Module", "CAFIX": "已知杀软进程,名称暂未收录", "BITDEFENDER": "已知杀软进程,名称暂未收录", "CFP": "COMODO", "CFPCONFIG": "已知杀软进程,名称暂未收录", "CLAMTRAY": "已知杀软进程,名称暂未收录", "CLAMWIN": "ClamWin Portable", "CUREIT": "DrWeb CureIT", "DRVIRUS": "已知杀软进程,名称暂未收录", "DRWADINS": "Dr.Web", "DRWEB": "Dr.Web", "DEFENDERDAEMON": "ShadowDefender", "DWEBLLIO": "已知杀软进程,名称暂未收录", "DWEBIO": "已知杀软进程,名称暂未收录", "ESCANH95": "已知杀软进程,名称暂未收录", "EWIDOCTRL": "Ewido Security Suite", "EZANTIVIRUSREGISTRATIONCHECK": "e-Trust Antivirus", "FILEMON": "已知杀软进程,名称暂未收录", "FORTICLIENT": "已知杀软进程,名称暂未收录", "FORTISCAN": "已知杀软进程,名称暂未收录", "FPAVSERVER": "已知杀软进程,名称暂未收录", "FPROTTRAY": "F-PROT Antivirus", "FPWIN": "Verizon", "FRESHCLAM": "ClamAV", "FSBWSYS": "F-secure", "F-SCHED": "已知杀软进程,名称暂未收录", "FSDFWD": "F-Secure", "FSGK32ST": "F-Secure", "FSGUIEXE": "已知杀软进程,名称暂未收录", "FSPEX": "已知杀软进程,名称暂未收录", "FSSM32": "F-Secure", "GCASDTSERV": "已知杀软进程,名称暂未收录", "GCASSERV": "已知杀软进程,名称暂未收录", "GIANTANTISPYWARE": "已知杀软进程,名称暂未收录", "GUARDGUI": "网游保镖", "GUARDNT": "IKARUS", "GUARDXSERVICE": "已知杀软进程,名称暂未收录", "GUARDXKICKOFF": "已知杀软进程,名称暂未收录", "HREGMON": "已知杀软进程,名称暂未收录", "HRRES": "已知杀软进程,名称暂未收录", "HSOCKPE": "已知杀软进程,名称暂未收录", "HUPDATE": "已知杀软进程,名称暂未收录", "ICSSUPPNT": "已知杀软进程,名称暂未收录", "INETUPD": "已知杀软进程,名称暂未收录", "INOCIT": "eTrust", "INORPC": "eTrust", "INORT": "eTrust", "INOTASK": "eTrust", "INOUPTNG": "eTrust", "ISAFE": "eTrust", "ISATRAY": "已知杀软进程,名称暂未收录", "KAV": "Kaspersky", "KAVMM": "Kaspersky", "KAVPFW": "Kaspersky", "KAVSTART": "Kaspersky", "KAVSVC": "Kaspersky", "KAVSVCUI": "Kaspersky", "KMAILMON": "金山毒霸", "MAMUTU": "已知杀软进程,名称暂未收录", "MCREGWIZ": "McAfee", "MYAGTSVC": "McAfee", "MYAGTTRY": "McAfee", "NEOWATCHTRAY": "NeoWatch", "NPAVTRAY": "已知杀软进程,名称暂未收录", "NPFMSG": "Norman个人防火墙", "NSMDTR": "Norton", "NSSSERV": "已知杀软进程,名称暂未收录", "NSSTRAY": "已知杀软进程,名称暂未收录", "NTOS": "已知杀软进程,名称暂未收录", "NVCOD": "已知杀软进程,名称暂未收录", "NVCTE": "已知杀软进程,名称暂未收录", "NVCUT": "已知杀软进程,名称暂未收录", "OFCPFWSVC": "OfficeScanNT", "ONLINENT": "已知杀软进程,名称暂未收录", "OPSSVC": "已知杀软进程,名称暂未收录", "OP_MON": " OutpostFirewall", "PAVFIRES": "熊猫卫士", "PAVFNSVR": "熊猫卫士", "PAVKRE": "熊猫卫士", "PAVPROT": "熊猫卫士", "PAVPRSRV": "熊猫卫士", "PAVSRV51": "熊猫卫士", "PAVSS": "熊猫卫士", "PCCGUIDE": "PC-cillin", "PCCIOMON": "PC-cillin", "PCCNTMON": "PC-cillin", "PCCPFW": "趋势科技", "PCCTLCOM": "趋势科技", "PCTAV": "PC Tools AntiVirus", "PERTSK": "已知杀软进程,名称暂未收录", "PERVAC": "已知杀软进程,名称暂未收录", "PESTPATROL": "Ikarus", "PNMSRV": "已知杀软进程,名称暂未收录", "PREVSRV": "熊猫卫士", "PREVX": "已知杀软进程,名称暂未收录", "PSIMSVC": "已知杀软进程,名称暂未收录", "QHONLINE": "已知杀软进程,名称暂未收录", "QHONSVC": "已知杀软进程,名称暂未收录", "QHWSCSVC": "已知杀软进程,名称暂未收录", "QHSET": "已知杀软进程,名称暂未收录", "SALITY": "已知杀软进程,名称暂未收录", "SAPISSVC": "已知杀软进程,名称暂未收录", "SCANWSCS": "已知杀软进程,名称暂未收录", "SAVADMINSERVICE": "SAV", "SAVMAIN": "SAV", "SAVSCAN": "SAV", "SCANNINGPROCESS": "已知杀软进程,名称暂未收录", "SDRA64": "已知杀软进程,名称暂未收录", "SDHELP": "Spyware Doctor", "SITECLI": "已知杀软进程,名称暂未收录", "SPBBCSVC": "Symantec", "SPIDERCPL": "Dr.Web", "SPIDERML": "Dr.Web", "SPIDERUI": "Dr.Web", "SPYBOTSD": "Spybot ", "STOPSIGNAV": "已知杀软进程,名称暂未收录", "SWAGENT": "SonicWALL", "SWDOCTOR": "SonicWALL", "SWNETSUP": "Sophos", "SYMLCSVC": "Symantec", "SYMSPORT": "Sysmantec", "SYMWSC": "Sysmantec", "SYNMGR": "Sysmantec", "TMLISTEN": "趋势科技", "TMNTSRV": "趋势科技", "TMPROXY": "趋势科技", "TNBUTIL": "Anti-Virus", "VBA32ECM": "已知杀软进程,名称暂未收录", "VBA32IFS": "已知杀软进程,名称暂未收录", "VBA32LDR": "已知杀软进程,名称暂未收录", "VBA32PP3": "已知杀软进程,名称暂未收录", "VBSNTW": "已知杀软进程,名称暂未收录", "VCRMON": "VirusChaser", "VRFWSVC": "已知杀软进程,名称暂未收录", "VRMONNT": "HAURI", "VRMONSVC": "HAURI", "VRRW32": "已知杀软进程,名称暂未收录", "WINSSNOTIFY": "已知杀软进程,名称暂未收录", "XCOMMSVR": "BitDefender", "ZLCLIENT": "已知杀软进程,名称暂未收录", "360RP": "360杀毒", "AFWSERV": " Avast Antivirus ", "SAFEBOXTRAY": "360杀毒", "360SAFEBOX": "360杀毒", "QQPCTRAY": "QQ电脑管家", "KSAFETRAY": "金山毒霸", "KSAFESVC": "金山毒霸", "KWATCH": "金山毒霸", "AVGCSRVX": "AVG", "GOV_DEFENCE_SERVICE": "云锁", "GOV_DEFENCE_DAEMON": "云锁"}
	yuan:=command("/c tasklist /svc")
	jc:=regexp.MustCompile(".*[.]exe").FindAll(yuan,-1)
	_=data
	for _,tk:=range jc{
		av:=data[strings.Split(strings.ToTitle(string(tk)),".")[0]]
		if len(av)>0{
			pname:=fmt.Sprintf("Antivirus:%s info:%s",av,string(regexp.MustCompile(fmt.Sprintf("%s.*",tk)).FindAll(yuan,-1)[0]))
			fmt.Println(pname)
		}
	}

}

func main()  {
	var u=flag.Bool("u",false,"Get user information and host information")
	var s=flag.Bool("s",false,"Get service information")
	var r=flag.Bool("r",false,"Registry check")
	var i=flag.Bool("i",false,"Internet Information")
	var b=flag.Bool("b",false,"Patch query")
	var a=flag.Bool("a",false,"Antivirus judgment")
	var all=flag.Bool("all",false,"Collect all")
	flag.Usage=usage
	flag.Parse()
	if *u {
		userinfo()
		local()
		processinfo()
	}else if *s {
		services()
	}else if *r {
		registryinfo()
	} else if *i {
		internetinfo()
	}else if *b {
		patchinfo()
	}else if *a {
		avexists()
	}else if *all{
		userinfo()
		local()
		processinfo()
		services()
		registryinfo()
		internetinfo()
		patchinfo()
		avexists()
	}else{
		usage()
		flag.PrintDefaults()
	}

}
