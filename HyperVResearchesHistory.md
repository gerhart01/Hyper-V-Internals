# Hyper-V internals researches history (2006-2024) <!-- omit in toc -->

- [ Hyper-V internals researches](#hyper-v-internals-researches)
- [ MSDN and other Microsoft sources](#msdn-and-other-microsoft-sources)
	- [ Headers from official Windows SDK\\WDK](#headers-from-official-windows-sdkwdk)
		- [ WDK](#wdk)
		- [ SDK](#sdk)
- [ VBS\\VSM researches](#vbsvsm-researches)
- [ Hyper-V related free and open source utilities, scripts, schemes](#hyper-v-related-free-and-open-source-utilities-scripts-schemes)
- [ Software and tools, working with Hyper-V](#software-and-tools-working-with-hyper-v)
- [ Other sources, interesting links and Hyper-V related materials](#other-sources-interesting-links-and-hyper-v-related-materials)

# &nbsp;Hyper-V internals researches

**[23.05.2006]** *[Microsoft]* Jake Oshins. Device Virtualization Architecture. WinHec 2006. [Link](https://web.archive.org/web/20170808015836/https://cs.nyu.edu/courses/fall14/CSCI-GA.3033-010/Microsoft-Virtual-Devices.pdf)  
**[01.08.2007]** *[Microsoft]* Brandon Baker. Windows Server Virtualization and The Windows Hypervisor. [Link](https://www.blackhat.com/presentations/bh-usa-07/Baker/Presentation/BH07_Baker_WSV_Hypervisor_Security.pdf)  
**[19.01.2011]** Matthieu Suiche [(msuiche.com)](https://www.msuiche.com). LiveCloudKd. Your cloud is on my pocket. BlackHat DC 2011. [Link](https://media.blackhat.com/bh-dc-11/Suiche/BlackHat_DC_2011_Suiche_Cloud%20Pocket-Slides.pdf)  
**[14.06.2011]** Nicolas Economou [(@nicoeconomou)](https://twitter.com/nicoeconomou). Hyper-V Vmbus persistent DoS vulnerability. [Link](https://www.coresecurity.com/content/hyperv-vmbus-persistent-dos-vulnerability)  
**[04.09.2013]** Arthur Khudyaev [(@gerhart_x)](https://twitter.com/gerhart_x). Hyper-V debugging for beginners. [Link](https://www.securitylab.ru/contest/444112.php). [English version](https://hvinternals.blogspot.com/2015/10/hyper-v-debugging-for-beginners.html)  
**[08.01.2014]** Arthur Khudyaev [(@gerhart_x)](https://twitter.com/gerhart_x). Hyper-V debugging for beginners. Part 2 or half disclosure of MS13-092 (1-day exploit research). [Link](https://www.securitylab.ru/contest/448457.php). [English version](https://hvinternals.blogspot.com/2017/10/hyper-v-debugging-for-beginners-part-2.html)  
**[02.06.2014]** Felix Wilhelm [(@_fel1x)](https://twitter.com/_fel1x), Matthias Luft [(@uchi_mata)](https://twitter.com/uchi_mata). Security Assessment of Microsoft Hyper-V. MS13-092 full disclosure. [Link](https://static.ernw.de/whitepaper/ERNW_Newsletter_43_HyperV_en.pdf)  
**[29.05.2014]** Felix Wilhelm [(@_fel1x)](https://twitter.com/_fel1x), Matthias Luft  [(@uchi_mata)](https://twitter.com/uchi_mata), Enno Rey [(@enno_insinuator)](https://twitter.com/enno_insinuator). Compromise-as-a-Service. Our PleAZURE. HitB Ams 2014 [Link](https://www.ernw.de/download/ERNW_HITBAMS14_HyperV_fwilhelm_mluft_erey.pdf)  
**[27.03.2015]** Alex Ionescu [(@aionescu)](https://twitter.com/aionescu). Ring 0 to Ring -1 Attacks. Hyper-V IPC Internals. [Link. Web Archive](http://web.archive.org/web/20190419095356/http://www.alex-ionescu.com/syscan2015.pdf)  
**[04.01.2016]** Hyper-V vmswitch.sys VmsMpCommonPvtHandleMulticastOids Guest to Host Kernel-Pool Overflow. [Link](https://bugs.chromium.org/p/project-zero/issues/detail?id=688)  
**[04.01.2016]** Hyper-V vmswitch.sys VmsVmNicHandleRssParametersChange OOBR Guest to Host BugChecks. [Link](https://bugs.chromium.org/p/project-zero/issues/detail?id=689)  
**[04.01.2016]** Hyper-V vmswitch.sys VmsPtpIpsecTranslateAddv2toAddv2Ex OOBR Guest to Host BugCheck. [Link](https://bugs.chromium.org/p/project-zero/issues/detail?id=690)  
**[17.06.2017]** *[Microsoft]* Andrea Allievi [(@aall86)](https://twitter.com/aall86). The Hyper-V Architecture and its Memory Manager. [Link. Web Archive](https://web.archive.org/web/20200103231355/https://www.andrea-allievi.com/files/Recon_2017_Montreal_HyperV_public.pptx)  
**[22.03.2017]** Aleksandr Bazhaniuk [(@ABazhaniuk)](https://twitter.com/ABazhaniuk), Mikhail Gorobets [@mikhailgorobets](https://twitter.com/mikhailgorobets), Andrew Furtak, Yuriy Bulygin [@c7zero](https://twitter.com/c7zero). Attacking hypervisors through hardware emulation. [Link](https://www.troopers.de/downloads/troopers17/TR17_Attacking_hypervisor_through_hardwear_emulation.pdf)  
**[09.08.2017]** Arthur Khudyaev [(@gerhart_x)](https://twitter.com/gerhart_x). Hyper-V sockets internals. [Link](https://xakep.ru/2017/08/09/hyper-v-internals). [English version](https://hvinternals.blogspot.com/2017/09/hyperv-socket-internals.html)  
**[19.06.2018]** *[Microsoft]* Benjamin Armstrong [(@vbenarmstrong)](https://twitter.com/vbenarmstrong). Hyper-V API Overview. [Link](https://interopevents.blob.core.windows.net/events/2018/Redmond/Day%202/Track%201/docs/917318-2_21_1130_State%20of%20Hyper-V%20API%20World.pdf)  
**[08.08.2018]** *[Microsoft]* Nicolas Joly [(@n_joly)](https://twitter.com/n_joly), Joe Bialek [(@josephbialek)](https://twitter.com/josephbialek). A Dive in to Hyper-V Architecture & Vulnerabilities. [Link](https://i.blackhat.com/us-18/Wed-August-8/us-18-Joly-Bialek-A-Dive-in-to-Hyper-V-Architecture-and-Vulnerabilities.pdf)  
**[09.08.2018]** *[Microsoft]* Jordan Rabet [(@smealum)](https://twitter.com/smealum). Hardening Hyper-V through Offensive Security Research. CVE-2017-0075. [Link](https://i.blackhat.com/us-18/Thu-August-9/us-18-Rabet-Hardening-Hyper-V-Through-Offensive-Security-Research.pdf)  
**[14.08.2018]** *[Microsoft]* Hyper-V HyperClear Mitigation for L1 Terminal Fault. [Link](https://techcommunity.microsoft.com/t5/Virtualization/Hyper-V-HyperClear-Mitigation-for-L1-Terminal-Fault/ba-p/382429). [Update](https://techcommunity.microsoft.com/t5/Virtualization/5-14-Hyper-V-HyperClear-Update/ba-p/566499)  
**[18.12.2018]** *[Microsoft]* Windows Sandbox. [Link](https://techcommunity.microsoft.com/t5/Windows-Kernel-Internals/Windows-Sandbox/ba-p/301849)  
**[08.11.2018]** Yunhai Zhang [(@_f0rgetting_)](https://twitter.com/_f0rgetting_). Dive Into Windows Defender Application Guard. [Link](https://www.powerofcommunity.net/poc2018/yunhai.pdf)  
**[10.12.2018]** *[Microsoft]* Saar Amar [(@AmarSaar)](https://twitter.com/AmarSaar). First Steps in Hyper-V Research. [Link](https://msrc.microsoft.com/blog/2018/12/first-steps-in-hyper-v-research/)  
**[27.01.2019]** Alex Ionescu [(@aionescu)](https://twitter.com/aionescu). Writing a Hyper-V “Bridge” for Fuzzing — Part 2 : Hypercalls & MDLs. [Link](https://www.alex-ionescu.com/?p=471)  
**[28.01.2019]** *[Microsoft]* Fuzzing para-virtualized devices in Hyper-V. [Link](https://msrc.microsoft.com/blog/2019/01/fuzzing-para-virtualized-devices-in-hyper-v/)  
**[15.02.2019]** Amardeep Chana. Ventures into Hyper-V - Fuzzing hypercalls. [Link](https://labs.withsecure.com/publications/ventures-into-hyper-v-part-1-fuzzing-hypercalls)  
**[15.02.2019]** *[Microsoft]* Daniel King [(@long123king)](https://twitter.com/long123king), Shawn Denbow [@sdenbow](https://twitter.com/sdenbow). Growing Hypervisor 0day with Hyperseed. [Link](https://github.com/Microsoft/MSRC-Security-Research/blob/master/presentations/2019_02_OffensiveCon/2019_02%20-%20OffensiveCon%20-%20Growing%20Hypervisor%200day%20with%20Hyperseed.pdf)  
**[25.03.2019]** Bruce Dang [(@brucedang)](https://twitter.com/brucedang). Some notes on identifying exit and hypercall handlers in Hyper-V. [Link](https://gracefulbits.wordpress.com/2019/03/25/some-notes-on-identifying-exit-and-hypercall-handlers-in-hyperv/) [Link.Web Archive](https://web.archive.org/web/20200210200349/https://gracefulbits.com/2019/03/25/some-notes-on-identifying-exit-and-hypercall-handlers-in-hyperv/)  
**[08.08.2019]** *[Microsoft]* Joe Bialek [(@josephbialek)](https://twitter.com/josephbialek). Exploiting the Hyper-V IDE Emulator to Escape the Virtual Machine. [Link](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2019_08_BlackHatUSA/BHUSA19_Exploiting_the_Hyper-V_IDE_Emulator_to_Escape_the_Virtual_Machine.pdf)  
**[04.09.2019]** Arthur Khudyaev [(@gerhart_x)](https://twitter.com/gerhart_x). Hyper-V memory internals. Guest OS memory access   
* [Russian version](https://www.securitylab.ru/contest/500796.php)   
* [English version](https://hvinternals.blogspot.com/2019/09/hyper-v-memory-internals-guest-os-memory-access.html) [10.09.2019]

**[11.09.2019]** *[Microsoft]* Saar Amar [(@AmarSaar)](https://twitter.com/AmarSaar). Attacking the VM Worker Process. [Link](https://msrc.microsoft.com/blog/2019/09/attacking-the-vm-worker-process/)  
**[14.05.2020]** Alisa Shevchenko [(@alisaesage)](https://twitter.com/alisaesage). Hyper-V Linux integration services description. [Link](https://re.alisa.sh/notes/Hyper-V-LIS.html)  
**[04.06.2020]** Damien Aumaitre. Fuzz and Profit with WHVP. [Link](https://www.sstic.org/media/SSTIC2020/SSTIC-actes/fuzz_and_profit_with_whvp/SSTIC2020-Slides-fuzz_and_profit_with_whvp-aumaitre.pdf)  
**[19.06.2020]** Arthur Khudyaev [(@gerhart_x)](https://twitter.com/gerhart_x). Hyper-V memory internals. EXO partition memory access. 
* [English version](https://hvinternals.blogspot.com/2020/06/hyper-v-memory-internals-exo-partition.html)  
* [Russian version](https://xakep.ru/2020/06/24/hyper-v-exo/) [24.06.2020]  

**[03.09.2020]** Arthur Khudyaev [(@gerhart_x)](https://twitter.com/gerhart_x). Windows Hyper-V Denial of Service vulnerability internals in nested virtualization component (CVE-2020-0890). [Link](https://hvinternals.blogspot.com/2020/09/hyper-v-nested-virtualization-dos.html)  
**[10.09.2020]** Daniel Fernandez Kuehr [(@ergot86)](https://twitter.com/ergot86). Microsoft Hyper-V Stack Overflow Denial of Service (CVE-2020-0751). [Link](https://labs.bluefrostsecurity.de/advisories/bfs-sa-2020-001)  
**[10.09.2020]** Daniel Fernandez Kuehr [(@ergot86)](https://twitter.com/ergot86). Microsoft Hyper-V Type Confusion leading to Arbitrary Memory Dereference (CVE-2020-0904). [Link](https://labs.bluefrostsecurity.de/advisories/bfs-sa-2020-003)  
**[14.11.2020]** Alisa Shevchenko [(@alisaesage)](https://twitter.com/alisaesage). Hypervisor vulnerability research (slides 35-60). [Link](https://alisa.sh/slides/HypervisorVulnerabilityResearch2020.pdf)  
**[25.12.2020]** Arthur Khudyaev [(@gerhart_x)](https://twitter.com/gerhart_x). Hyper-V debugging for beginners (2nd edition).
* [Russian version](https://xakep.ru/2020/12/25/hyperv-hyperdebug/)  
* [English version](https://hvinternals.blogspot.com/2021/01/hyper-v-debugging-for-beginners-2nd.html) [11.01.2021] 
       
**[15.02.2021]** Alisa Shevchenko [(@alisaesage)](https://twitter.com/alisaesage). Microsoft Hyper-V Virtual Network Switch VmsMpCommonPvtSetRequestCommon Out of Bounds Read. [Link](https://zerodayengineering.com/research/hyper-v-vmswitch-oobr.html)  
**[11.03.2021]** Alex Ilgayev [(@_alex_il_)](https://twitter.com/_alex_il_). Playing in the Microsoft Windows Sandbox. [Link](https://research.checkpoint.com/2021/playing-in-the-windows-sandbox/)  
**[20.04.2021]** [(@_xeroxz)](https://twitter.com/_xeroxz). Voyager - A Hyper-V Hacking Framework. [Link](https://back.engineering/20/04/2021/)   
**[31.05.2021]** Axel Souchet [(@0vercl0k)](https://twitter.com/0vercl0k). CVE-2021-28476: a guest-to-host "Microsoft Hyper-V Remote Code Execution Vulnerability" in vmswitch.sys (PoC). [Link](https://github.com/0vercl0k/CVE-2021-28476)  
**[02.06.2021]** Diane Dubois [(@0xdidu)](https://twitter.com/0xdidu). Hyntrospect: a fuzzer for Hyper-V devices (video and slides).[Link](https://www.sstic.org/2021/presentation/hyntrospect_a_fuzzer_for_hyper-v_devices/)  
**[02.06.2021]** Daniel Fernandez Kuehr [(@ergot86)](https://twitter.com/ergot86). Microsoft Hyper-V: Multiple Vulnerabilities in vmswitch.sys (CVE-2021-28476) [Link](https://labs.bluefrostsecurity.de/advisories/bfs-sa-2021-001/)  
**[28.07.2021]** Ophir Harpaz [(@OphirHarpaz)](https://twitter.com/OphirHarpaz), Peleg Hadar [(@peleghd)](https://twitter.com/peleghd). Critical 9.9 Vulnerability In Hyper-V Allowed Attackers To Exploit Azure [Link](https://www.guardicore.com/labs/critical-vulnerability-in-hyper-v-allowed-attackers-to-exploit-azure/)  
**[29.07.2021]** Salma el Mohib [(@lychnis42)](https://twitter.com/lychnis42). A virtual journey: From hardware virtualization to Hyper-V's Virtual Trust Levels. 
* [Article](https://blog.quarkslab.com/a-virtual-journey-from-hardware-virtualization-to-hyper-vs-virtual-trust-levels.html) 
* [Script from article](https://github.com/quarkslab/windbg-vtl)   

**[04.08.2021]** Ophir Harpaz [(@OphirHarpaz)](https://twitter.com/OphirHarpaz), Peleg Hadar [(@peleghd)](https://twitter.com/peleghd). hAFL1 – Our Journey of Fuzzing Hyper-V and Discovering a Critical 0-Day. [Link](https://www.guardicore.com/labs/hafl1-our-journey-of-fuzzing-hyper-v-and-discovering-a-critical-0-day/). [Link. Web Archive](http://web.archive.org/web/20220503161436/https://www.guardicore.com/labs/critical-vulnerability-in-hyper-v-allowed-attackers-to-exploit-azure/)  
* Hyper-V’s virtual switch (vmswitch.sys) fuzzer. [Link](https://github.com/SB-GC-Labs/hAFL1)	  
* Black Hat 2021 presentation. [Link](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Hafl1-Our-Journey-Of-Fuzzing-Hyper-V-And-Discovering-A-0-Day.pdf)  

**[04.08.2021]** Zhenhao Hon [(@rthhh17)](https://twitter.com/rthhh17), Chuanjian Lia. Mobius Band: Explore Hyper-V Attack Interface through Vulnerabilities Internals. 
* [Blackhat 2021 Presentation](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Mobius-Band-Explore-Hyper-V-Attack-Interface-Through-Vulnerabilities-Internals.pdf)  
* [Slides](https://github.com/howknows/hypervvulners_bhusa2021/blob/main/2021-BHUSA-Mobius_Band_Explore_Hyper-V_Attack_Interface_through_Vulnerabilities_Internals-Hong.pptx)  
* [Video](https://www.youtube.com/watch?v=7VI-_r_jrfQ)    

**[02.09.2021]** *[Microsoft]* Xinyang Ge, Ben Niu, Robert Brotzman, Yaohui Chen, HyungSeok Han, Patrice Godefroid, Weidong Cui. HyperFuzzer: An Efficient Hybrid Fuzzer for Virtual CPUs.[Link](https://www.microsoft.com/en-us/research/uploads/prod/2021/09/hyperfuzzer-ccs21.pdf)  
**[04.01.2022]** Peter Hlavaty [(@rezer0dai)](https://twitter.com/rezer0dai). Bug Bounties and HyperV RCE Research (CVE-2020-17095). [Link](https://rezer0dai.github.io/biug-bounties/)   
**[03.03.2022]** Diane Dubois [(@0xdidu)](https://twitter.com/0xdidu). Hyntrospect: a fuzzer for Hyper-V devices. 
* [Slides](https://github.com/0xdidu/Presentations/blob/main/BHIL2022_Hyntrospect.pdf)   
* [Video](https://www.youtube.com/watch?v=kRG-W-HPQPI)  

**[21.04.2022]** VictorV [(@vv474172261)](https://twitter.com/vv474172261). Old School. New Story. Escape from Hyper-V by path traversal.[Slides](https://bit.ly/38AS9qd)  
**[23.05.2022]** Connor McGarr [(@33y0re)](https://twitter.com/33y0re). Exploit Development. Living The Age of VBS, HVCI, and Kernel CFG.[Link](https://connormcgarr.github.io/hvci/)  
**[11.08.2022]** Zhenhao Hon [(@rthhh17)](https://twitter.com/rthhh17), Ziming Zhang [(@ezrak1e)](https://twitter.com/ezrak1e). DirectX: The New Hyper-V Attack Surface. [Link](https://i.blackhat.com/USA-22/Thursday/US-22-Hong-DirectX-The-New-Hyper-V-Attack-Surface.pdf)  
**[08.12.2022]** Andrew Ruddick	[(@arudd1ck)](https://twitter.com/arudd1ck), Rohit Mothe [(@rohitwas)](https://twitter.com/rohitwas). Exploring a New Class of Kernel Exploit Primitive. [Link](https://i.blackhat.com/EU-22/Thursday-Briefings/EU-22-Ruddick-Exploring-a-New-Class-of-Kernel-Exploit-Primitive.pdf)  
**[14.12.2022]** Ben Barnea [(@nachoskrnl)](https://twitter.com/nachoskrnl). CVE-2022-37998 and CVE-2022-37973 (DoS Microsoft Defender Application Guard, Sandbox) description. [Link](https://www.akamai.com/blog/security-research/msrpc-lsm-cve-disturbing-hosts-rest)   
**[16.05.2023]** Aryan Xyrem [(@Xyrem256)](https://twitter.com/Xyrem256). Exploiting Windows vulnerabilities with Hyper-V: A Hacker’s swiss army knife. [Link](https://reversing.info/posts/hyperdeceit/)   
**[07.09.2023]** Francisco Falcon [(@fdfalcon)](https://twitter.com/fdfalcon). Debugging Windows Isolated User Mode (IUM) Processes. [Link](https://blog.quarkslab.com/debugging-windows-isolated-user-mode-ium-processes.html)  
**[15.09.2023]** Matt Hand [(@matterpreter)](https://twitter.com/matterpreter). Hypervisor Detection with SystemHypervisorDetailInformation. [Link](https://medium.com/@matterpreter/hypervisor-detection-with-systemhypervisordetailinformation-26e44a57f80e)  
**[08.10.2023]** [(@Pwndorei)](https://twitter.com/lkjuio3865) and [(@l0ch)](https://twitter.com/l0ch_pwn). Microsoft Hyper-V CVE-2018-0959 analysis 
  * [Part1 (Korean version)](https://hackyboiz.github.io/2023/10/08/pwndorei/newjeans-hyper-v-pt2)
  * [Part2 (Korean version)](https://hackyboiz.github.io/2023/10/15/pwndorei/newjeans-hyper-v-pt3)
  * [Part3 (Korean version)](https://hackyboiz.github.io/2023/10/22/pwndorei/newjeans-hyper-v-pt4)
  * [Part4 (Korean version)](https://hackyboiz.github.io/2023/10/30/pwndorei/newjeans-hyper-v-pt5). [Video](https://www.youtube.com/watch?v=LvtNtkAll84&t=106s)  

**[20.11.2023]** Satoshi Tanda [(@standa_t)](https://twitter.com/standa_t). Microsoft Hyper-V CVE-2023-36427 vulnerability description and PoC. [Link](https://github.com/tandasat/CVE-2023-36427)  
**[12.05.2024]** [(@Pwndorei)](https://twitter.com/lkjuio3865). CVE-2023-36407 Analysis & Exploitation. [Link](https://hackyboiz.github.io/2024/05/12/pwndorei/newjeans-hyper-v-pt7/)
	
[Microsoft] - research was made by employee of Hyper-V creators company

# &nbsp;MSDN and other Microsoft sources

Managing Hyper-V hypervisor scheduler types: [Link](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/manage/manage-hyper-v-scheduler-types)  
Hyper-V top level functional specification (web-version): [Link](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/tlfs)  
Hyper-V top level functional specifications: [Link](https://github.com/MicrosoftDocs/Virtualization-Documentation/tree/live/tlfs)  
Linux kernel for Hyper-V root partition [Link](https://lore.kernel.org/linux-hyperv/)  
Windows Powershell modules: [Hyper-V sockets example](https://github.com/PowerShell/PowerShell/blob/master/src/System.Management.Automation/engine/remoting/common/RemoteSessionHyperVSocket.cs)  

Host Compute Network (HCN) service API for VMs and containers: [Link](https://github.com/microsoft/hcsshim)  
Windows classic samples (Hyper-V): [Link](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/Hyper-V)  
SkTool - Hypervisor / Secure Kernel / Secure Mitigations Parser Tool from Windows SDK


(Windows Internals book, Hyper-V TLFS, another MSDN docs are standard Hyper-V internals information sources)  

## &nbsp;Headers from official Windows SDK\WDK  
### &nbsp;WDK
- hypervdevicevirtualization.h  
- VmbusKernelModeClientLibApi.h  
- pcivirt.h  

### &nbsp;SDK  
- vmsavedstatedump.h
- vmsavedstatedumpdefs.h
- WinHvEmulation.h
- WinHvPlatform.h
- WinHvPlatformDefs.h
- wmcontainer.h
- Wmcontainer.idl

# &nbsp;VBS\VSM researches

I'm not specalized in VBS, which is Hyper-V based security mechanism, therefore i give links on papers, because they can contain some information about Hyper-V internals. 

[06.08.2015] Alex Ionescu [(@aionescu)](https://twitter.com/aionescu). BATTLE OF SKM AND IUM. [Link](https://web.archive.org/web/20190728160948/http://www.alex-ionescu.com/blackhat2015.pdf)  
[10.12.2015] Guillaume C. Windows 10 VSM Présentation des nouveautés et implémentations. [Link](https://www.ossir.org/bretagne/supports/2015/201512/win10vsm.pdf)  
[04.08.2016] Rafal Wojtczuk. Analysis of the Attack Surface of Windows 10 Virtualization-Based Security]
   
  * [Presentation](https://www.blackhat.com/docs/us-16/materials/us-16-Wojtczuk-Analysis-Of-The-Attack-Surface-Of-Windows-10-Virtualization-Based-Security.pdf)  
  * [Whitepaper](https://www.blackhat.com/docs/us-16/materials/us-16-Wojtczuk-Analysis-Of-The-Attack-Surface-Of-Windows-10-Virtualization-Based-Security-wp.pdf)
  
[02.02.2017] Adrien Chevalier [(@0x00_ach)](https://twitter.com/0x00_ach). Virtualization Based Security - Part 1: The boot process. [Link. Web Archive](https://web.archive.org/web/20210619092627/http://blog.amossys.fr/virtualization-based-security-part1.html)  
[13.02.2017] Adrien Chevalier [(@0x00_ach)](https://twitter.com/0x00_ach). Virtualization Based Security - Part 2: kernel communications. [Link. Web Archive](https://web.archive.org/web/20201111203054/https://blog.amossys.fr/virtualization-based-security-part2.html)  
[15.07.2017] Hans Kristian Brendmo. Live forensics on the Windows 10 secure kernel. [Link](https://pdfs.semanticscholar.org/e275/cc28c5c8e8e158c45e5e773d0fa3da01e118.pdf)  
[27.06.2018] Alex Ionescu [(@aionescu)](https://twitter.com/aionescu), David Weston [@dwizzzleMSFT](https://twitter.com/dwizzzleMSFT). Inside the Octagon. Analyzing System Guard Runtime Attestation. OPCDE 2018. [Link](https://web.archive.org/web/20180808153201/http://alex-ionescu.com/Publications/OPCDE/octagon.pdf)  
[04.07.2018] [Microsoft] Saar Amar [(@AmarSaar)](https://twitter.com/AmarSaar). VBS and VSM Internals. BlueHat IL 2018. [Link](https://github.com/saaramar/Publications/blob/master/BluehatIL_VBS_meetup/VBS_Internals.pdf)  
[14.03.2019] Federal office for information security (Germany). [(@BSI_Bund)](https://twitter.com/BSI_Bund). Work Package 6: Virtual Secure Mode. [Link](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/Workpackage6_Virtual_Secure_Mode.pdf?__blob=publicationFile&v=2)  
[14.03.2019] Federal office for information security (Germany). [(@BSI_Bund)](https://twitter.com/BSI_Bund). Work Package 7: Device Guard. [Link](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Cyber-Sicherheit/SiSyPHus/Workpackage7_Device_Guard.pdf?__blob=publicationFile&v=5)    
[22.05.2019] Dominik Phillips, Aleksandar Milenkoski [(@milenkowski)](https://twitter.com/milenkowski). Virtual Secure Mode: Initialization. [Link](https://github.com/ernw/Windows-Insight/blob/master/articles/VSM/vsm_init_signed.pdf)   
[22.05.2019] Aleksandar Milenkoski [(@milenkowski)](https://twitter.com/milenkowski). Virtual Secure Mode: Communication Interfaces. [Link](https://github.com/ernw/Windows-Insight/blob/master/articles/VSM/vsm_communication_signed.pdf)  
[22.05.2019] Aleksandar Milenkoski [(@milenkowski)](https://twitter.com/milenkowski). Virtual Secure Mode: Architecture Overview. [Link](https://github.com/ernw/Windows-Insight/blob/master/articles/VSM/vsm_architecture_signed.pdf)  
[30.10.2019] Aleksandar Milenkoski [(@milenkowski)](https://twitter.com/milenkowski). Interfaces Virtual Secure Mode: Protections of Communication. [Link](https://github.com/ernw/Windows-Insight/blob/master/articles/VSM/milenkoski_issrew_signed.pdf)   
[30.10.2019] Lukas Beierlieb, Lukas Ifflander, Aleksandar Milenkoski [(@milenkowski)](https://twitter.com/milenkowski), Charles F. Goncalves, Nuno Antunes, Samuel Kounev. Towards Testing the Software Aging Behavior of Hypervisor Hypercall Interfaces. [Link](https://github.com/ernw/Windows-Insight/blob/master/articles/VSM/milenkoski_issrew_signed.pdf)  
[07.08.2020] [Microsoft] Andrea Allievi [(@aall86)](https://twitter.com/aall86). Introducing Kernel Data Protection, a new platform security technology for preventing data corruption. [Link](https://www.microsoft.com/security/blog/2020/07/08/introducing-kernel-data-protection-a-new-platform-security-technology-for-preventing-data-corruption/)  
[12.07.2020] Yarden Shafir [(@yarden_shafir)](https://twitter.com/yarden_shafir). Secure Pool Internals : Dynamic KDP Behind The Hood. [Link](https://windows-internals.com/secure-pool)  
[04.08.2020] [Microsoft] Saar Amar [(@AmarSaar)](https://twitter.com/AmarSaar), Daniel King [(@long123king)](https://twitter.com/long123king). Breaking VSM by Attacking Secure Kernel. Hardening Secure Kernel through Offensive Research. [Link](https://github.com/microsoft/MSRC-Security-Research/blob/master/presentations/2020_08_BlackHatUSA/Breaking_VSM_by_Attacking_SecureKernel.pdf)  
[01.01.2022] Yarden Shafir [(@yarden_shafir)](https://twitter.com/yarden_shafir). HyperGuard – Secure Kernel Patch Guard: Part 1 – SKPG Initialization. [Link](https://windows-internals.com/hyperguard-secure-kernel-patch-guard-part-1-skpg-initialization/)  
[17.01.2022] Yarden Shafir [(@yarden_shafir)](https://twitter.com/yarden_shafir). HyperGuard – Secure Kernel Patch Guard: Part 2 – SKPG Extents. [Link](https://windows-internals.com/hyperguard-secure-kernel-patch-guard-part-2-skpg-extents/)  
[19.04.2022] Yarden Shafir [(@yarden_shafir)](https://twitter.com/yarden_shafir). HyperGuard Part 3 – More SKPG Extents. [Link](https://windows-internals.com/hyperguard-part-3-more-skpg-extents/)  
[08.09.2022] James Forshaw [(@tiraniddo)](https://twitter.com/tiraniddo). Windows: Credential Guard KerbIumGetNtlmSupplementalCredential Information Disclosure. [Link](https://bugs.chromium.org/p/project-zero/issues/detail?id=2306)  
[30.12.2022] Worawit Wang [(@sleepya_)](https://twitter.com/sleepya_). Code Execution against Windows HVCI. [Link](https://datafarm-cybersecurity.medium.com/code-execution-against-windows-hvci-f617570e9df0)  
[15.01.2024] Satoshi Tanda [(@standa_t)](https://twitter.com/standa_t). Hypervisor-Protected Code Integrity (HVCI) Security Feature Bypass Vulnerability disclosure
(CVE-2024-21305). [Link](https://tandasat.github.io/blog/2024/01/15/CVE-2024-21305.html)

# &nbsp;Hyper-V related free and open source utilities, scripts, schemes 

[2013-2024] Arthur Khudyaev [(@gerhart_x)](https://twitter.com/gerhart_x)
* Files and scripts to "Hyper-V debugging for beginners (2013)" article. [Link](https://yadi.sk/d/jJJGTL7xCuFAV)
* Files and scripts to "Hyper-V internals (2015)" article. [Link](https://yadi.sk/d/4xw2Y4UHOhdvcw)
* Files and scripts to "Hyper-V debugging for beginners. 2nd edition (2020)" article. [Link](https://github.com/gerhart01/Hyper-V-scripts/tree/master/Hyper-V-debugging.%202nd-edition)
* LiveCloudKd. [Link](https://github.com/gerhart01/LiveCloudKd)
* LiveCloudKd SDK. [Link](https://github.com/gerhart01/LiveCloudKd/tree/master/LiveCloudKdSdk)
  * LiveCloudKd Python SDK. [Link](https://github.com/gerhart01/LiveCloudKd/tree/master/LiveCloudKdPy)
  * LiveCloudKd .Net SDK. [Link](https://github.com/gerhart01/LiveCloudKd/tree/master/hvlibdotnet)
  * LiveCloudKd SDK examples. [Link](https://github.com/gerhart01/LiveCloudKd/tree/master/LiveCloudKdExample)
* Native Hyper-V reading memory example driver. [Link](https://github.com/gerhart01/LiveCloudKd/tree/master/hvmm)
* CVE-2020-0890 PoC sources with binary (Windows Hyper-V Denial of Service Vulnerability) [Link](https://github.com/gerhart01/hyperv_local_dos_poc)
* Hyper-V integration plugin for MemProcFS by [@UlfFrisk](https://twitter.com/UlfFrisk). 
  * Source code. [Link](https://github.com/gerhart01/LiveCloudKd/tree/master/leechcore_device_hvmm). 
  * Plugin description from [@UlfFrisk](https://twitter.com/UlfFrisk). [Link](https://github.com/ufrisk/LeechCore/wiki/Device_LiveCloudKd). [Distributive](https://github.com/gerhart01/LiveCloudKd/releases/download/v1.2.20230913/leechcore_hyperv_plugin_13.09.2023.zip)     
* LiveCloudKd EXDi plugin source code. [Link](https://github.com/gerhart01/LiveCloudKd/tree/master/ExdiKdSample)  
* LiveCloudKd EXDi plugin for Windows Secure Kernel debugging. [Link](https://github.com/gerhart01/LiveCloudKd/blob/master/ExdiKdSample/LiveDebugging.md)
* LiveCloudKd EXDi static plugin for reading and writing Hyper-V memory [Link](https://github.com/gerhart01/LiveCloudKd/releases/download/v2.5.5.20230530/LiveCloudKd.v2.5.5.20220530-release.zip)
* Hvcalls GUI - tool for extracting hypercalls from native Windows binaries. [Link](https://github.com/gerhart01/Hyper-V-Tools/tree/main/Extract.Hvcalls)
* Radare2 build for displaying Hyper-V internals information through kd connection [Link](https://yadi.sk/d/eDAD9gIMEcAYEg)  
* Hyper-V integration plugin for volatility [Link](https://github.com/gerhart01/Hyper-V-Tools/tree/main/Plugin_for_volatility). [Distributive](https://github.com/gerhart01/Hyper-V-Tools/releases/download/1.0.20221109/Hyper-V.Memory.Manager.plugin.for.volatility.v1.0.20221109.zip) 
* Hyper Views - utility for viewing Hyper-V memory page tables [Link](https://github.com/gerhart01/Hyper-V-Tools/tree/main/HyperViews)
* Scripts for Hyper-V researching: [Link](https://github.com/gerhart01/Hyper-V-scripts)
	 * Script for hypercalls table creation in IDA PRO. [Link](https://github.com/gerhart01/Hyper-V-scripts/blob/master/ida75/ida75_CreatemVmcallHandlersTableWin11Preview.py)
	 * Script for parsing VM_PROCESS_CONTEXT structure. [[Pykd version]](https://github.com/gerhart01/Hyper-V-scripts/blob/master/ParsePrtnStructure.py), [[JavaScript version]](https://github.com/gerhart01/Hyper-V-scripts/blob/master/ParsePrtnStructure.js)
	 * Script for displaying VMCS inside hvix64 (dynamic execution using WinDBG session in IDA PRO). [Link](https://github.com/gerhart01/Hyper-V-scripts/blob/master/display-vmcs.py)
	 * Script for automatic configuration of Guest OS debugging, using embedded vmms.exe capabilities. [Link](https://github.com/gerhart01/Hyper-V-scripts/blob/master/hyperv-dbg-2019.ps1)
	 * Script for getting some information from Windows Secure Kernel in runtime (IDT, loaded modules, syscall, decyphering SkiSecureServiceTable). [Link](https://github.com/gerhart01/Hyper-V-scripts/blob/master/securekernel_info_pykd.py) 
	 * Script for some Hyper-V hypercalls codes and names automatic extraction on Powershell. [Link](https://github.com/gerhart01/Hyper-V-scripts/tree/master/extract_hvcalls)
	 * Script for Hyper-V hypercalls codes and names automatic extraction with GUI on Powershell. [Link](https://github.com/gerhart01/Hyper-V-scripts/tree/master/extract_hvcalls_gui)
	 * Scripts for Hyper-V sockets analysis (scripts were written for Hyper-V sockets internals article)
	 	* AfdEndpointListHead parsing [Link](https://github.com/gerhart01/Hyper-V-scripts/blob/master/ParseAfdEndpointListHead.py)	
		* AfdTlTransportListHead parsing [Link](https://github.com/gerhart01/Hyper-V-scripts/blob/master/ParseAfdTlTransportListHead.py)
* Hyper-V components scheme (Windows 11 23H2) [Link](https://github.com/gerhart01/Hyper-V-Internals/blob/master/Hyper-V%20components%20(Windows%2011%2023H2).png)
  
		
[2014, 2024] Marc-André Moreau [(@awakecoding)](https://twitter.com/awakecoding). 
* Hyper-V VmBusPipe [Link](https://github.com/awakecoding/VMBusPipe) 
* Tool for recompiling Hyper-V manager. [Link](https://github.com/awakecoding/hyper-v-manager). [Description](https://awakecoding.com/posts/decompiling-hyper-v-manager-to-rebuild-it-from-source/)  

[2016] Yuriy Bulygin [(@c7zero)](https://twitter.com/c7zero). Hyper-V VMBUS fuzzing. CHIPSEC: Platform Security Assessment Framework. [Link](https://github.com/chipsec/chipsec/tree/master/chipsec/modules/tools/vmm/hv)

[2018] Windows Hypervisor Platform API for Rust. [Link](https://crates.io/crates/libwhp)

[2018-2019] Alex Ionescu [(@aionescu)](https://twitter.com/aionescu). 
* Simpleator ("Simple-ator") is an innovative Windows-centric x64 user-mode application emulator that leverages several new features that were added in Windows 10 Spring Update (1803). [Link](https://github.com/ionescu007/Simpleator).  
* Hdk - Hyper-V development kit (unofficial). [Link](https://github.com/ionescu007/hdk)  

[2018] Matthieu Suiche [(msuiche.com)](https://www.msuiche.com). LiveCloudKd [Link](https://github.com/msuiche/LiveCloudKd)

[2019, 2021] Axel Souchet [(@0vercl0k)](https://twitter.com/0vercl0k). 
* Pywinhv. Python binding for the Microsoft Hypervisor Platform APIs. [Link](https://github.com/0vercl0k/pywinhv)
* What the fuzz. Cross-platform snapshot-based fuzzer designed for attacking user and or kernel-mode targets running on Microsoft Windows.  Windows Hypervisor Platform APIs is supported [Link](https://github.com/0vercl0k/wtf)

[2019, 2021] Behrooz Abbassi [(@BehroozAbbassi)](https://twitter.com/BehroozAbbassi) 
* ia32_msr_decoder.py. [Link](https://github.com/BehroozAbbassi/hyperv-research-scripts/blob/master/scripts/IA32-MSR-Decoder/ia32_msr_decoder.py)
* IA32_VMX_Helper.py. [Link](https://github.com/BehroozAbbassi/hyperv-research-scripts/blob/master/scripts/IA32-VMX-Helper/IA32_VMX_Helper.py)
* HypervCpuidInfo.h. Get Hyper-V CPUIDs information [Link](https://gist.github.com/BehroozAbbassi/8e07bae41b0b037a55259c19d00aa458) 
* VmwpMonitor. The VmwpMonitor is a DLL that must be injected to the vmwp.exe process to monitor the IO operations on the Emulated Devices between the Guest VM and the VM worker process. [Link](https://github.com/BehroozAbbassi/VmwpMonitor)

[2020] [(@commial)](https://twitter.com/commial). Configure Qemu-KVM for debugging SecureKernel [Link](https://github.com/commial/experiments/tree/master/debugging-secure-kernel)

[2020] Dmytro "Cr4sh" Oleksiuk [(@d_olex)](https://twitter.com/d_olex). Hyper-V backdoor, which allows to inspect Secure Kernel and run 3-rd party trustlets in the Isolated User Mode (a virtualization-based security feature of Windows 10). [Link](https://github.com/Cr4sh/s6_pcie_microblaze/tree/master/python/payloads/DmaBackdoorHv)

[2020] Matt Miller [(@epakskape)](https://twitter.com/epakskape) WHVP API based NOP-generator. [Link](https://github.com/epakskape/whpexp)

[2020] [(@_xeroxz)](https://twitter.com/_xeroxz) Hyper-V Hacking Framework For Windows 10 x64 (AMD & Intel). [Link](https://git.back.engineering/_xeroxz/Voyager)

[2021] Diane Dubois [(@0xdidu)](https://twitter.com/0xdidu). Hyntrospect. This tool is a coverage-guided fuzzer targeting Hyper-V emulated devices (in the userland of Hyper-V root partition). [Link](https://github.com/googleprojectzero/Hyntrospect)

[2021] Peleg Hadar [(@peleghd)](https://twitter.com/peleghd). hAFL2 is a kAFL-based hypervisor fuzzer. [Link](https://github.com/SafeBreach-Labs/hAFL2)

[2022] Abdelhamid Naceri [(@KLINIX5)](https://twitter.com/KLINIX5). Reverse RDP RCE example. [Link](https://github.com/klinix5/ReverseRDP_RCE)

[2022] Kenji Mouri (Qi Lu) [(@MouriNaruto)](https://twitter.com/MouriNaruto). NanaBox - open-source Hyper-V client based on Host Compute System API. [Link](https://github.com/M2Team/NanaBox)

[2023] Daniel Fernandoz Kuehr [(@ergot86)](https://twitter.com/ergot86). JS script for dumping hypervisor related structures [EPT,  VMCS, etc](https://github.com/ergot86/crap/blob/main/hyperv_stuff.js)

[2023] Aryan Xyrem [(@Xyrem256)](https://twitter.com/Xyrem256). Hypercall - library that allows you to impersonate as Hyper-V and intercept hypercalls done by the Windows kernel. [Link](https://github.com/Xyrem/HyperDeceit) 

[2023] Satoshi Tanda [(@standa_t)](https://twitter.com/standa_t). JS script for dumping hypervisor related structures [EPT, VMCS, MSR etc]. [Link](https://github.com/tandasat/hvext)

[2023] Or Ben-Porath [(@OrBenPorath)](https://twitter.com/OrBenPorath), CyberArk [(@CyberarkLabs)](https://twitter.com/CyberarkLabs). Fuzzer-V. [Link](https://github.com/cyberark/Fuzzer-V) 



# &nbsp;Software and tools, working with Hyper-V


Linux Integration Services (LIS). [Link](https://github.com/LIS)  
MemProcFS. [Link](https://github.com/ufrisk/MemProcFS)  

Qemu source code (WHPX support module). 
 * [Sources](https://github.com/qemu/qemu)
 * [Module](https://github.com/qemu/qemu/tree/master/hw/hyperv)

Virtual Box source code. 
 * [Sources](https://www.virtualbox.org/wiki/Downloads)
 * [Module](https://www.virtualbox.org/browser/vbox/trunk/src/VBox/VMM/VMMR3/NEMR3Native-win.cpp)

 # &nbsp;Other sources, interesting links and Hyper-V related materials

Notes for using Host Compute System API from Kenji Mouri (Qi Lu) [(@MouriNaruto)](https://twitter.com/MouriNaruto). [Link](https://github.com/MouriNaruto/MouriDocs/tree/main/docs/4)
