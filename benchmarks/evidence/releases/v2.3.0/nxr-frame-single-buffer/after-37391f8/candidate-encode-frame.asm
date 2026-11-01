
/home/jacek/.cache/rr-v230-nxr-frame-after/probe:     file format elf64-x86-64


Disassembly of section .text:

0000000000055340 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame>:
   55340:	55                   	push   %rbp
   55341:	41 57                	push   %r15
   55343:	41 56                	push   %r14
   55345:	41 55                	push   %r13
   55347:	41 54                	push   %r12
   55349:	53                   	push   %rbx
   5534a:	48 81 ec c8 01 00 00 	sub    $0x1c8,%rsp
   55351:	4c 8b b4 24 00 02 00 	mov    0x200(%rsp),%r14
   55358:	00 
   55359:	b0 0a                	mov    $0xa,%al
   5535b:	49 81 fe 66 1d 00 00 	cmp    $0x1d66,%r14
   55362:	0f 87 77 0a 00 00    	ja     55ddf <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa9f>
   55368:	44 8d 52 ff          	lea    -0x1(%rdx),%r10d
   5536c:	b0 0b                	mov    $0xb,%al
   5536e:	41 80 fa 01          	cmp    $0x1,%r10b
   55372:	0f 87 67 0a 00 00    	ja     55ddf <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa9f>
   55378:	b0 0c                	mov    $0xc,%al
   5537a:	40 80 fe 01          	cmp    $0x1,%sil
   5537e:	0f 87 5b 0a 00 00    	ja     55ddf <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa9f>
   55384:	4d 85 c0             	test   %r8,%r8
   55387:	74 45                	je     553ce <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x8e>
   55389:	49 8b 00             	mov    (%r8),%rax
   5538c:	49 ba 00 00 00 00 00 	movabs $0x8000000000000000,%r10
   55393:	00 00 80 
   55396:	49 31 c2             	xor    %rax,%r10
   55399:	48 85 c0             	test   %rax,%rax
   5539c:	b8 01 00 00 00       	mov    $0x1,%eax
   553a1:	49 0f 48 c2          	cmovs  %r10,%rax
   553a5:	48 85 c0             	test   %rax,%rax
   553a8:	74 26                	je     553d0 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x90>
   553aa:	48 83 f8 01          	cmp    $0x1,%rax
   553ae:	75 2b                	jne    553db <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x9b>
   553b0:	4d 8b 68 10          	mov    0x10(%r8),%r13
   553b4:	4d 8d 95 02 ff ff ff 	lea    -0xfe(%r13),%r10
   553bb:	41 b3 02             	mov    $0x2,%r11b
   553be:	b0 05                	mov    $0x5,%al
   553c0:	49 81 fa 03 ff ff ff 	cmp    $0xffffffffffffff03,%r10
   553c7:	73 1b                	jae    553e4 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa4>
   553c9:	e9 11 0a 00 00       	jmp    55ddf <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa9f>
   553ce:	eb 25                	jmp    553f5 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xb5>
   553d0:	41 bd 04 00 00 00    	mov    $0x4,%r13d
   553d6:	41 b3 01             	mov    $0x1,%r11b
   553d9:	eb 09                	jmp    553e4 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa4>
   553db:	41 bd 10 00 00 00    	mov    $0x10,%r13d
   553e1:	41 b3 03             	mov    $0x3,%r11b
   553e4:	66 41 83 78 18 00    	cmpw   $0x0,0x18(%r8)
   553ea:	0f 84 e0 01 00 00    	je     555d0 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x290>
   553f0:	44 88 5c 24 0f       	mov    %r11b,0xf(%rsp)
   553f5:	41 0f b7 c5          	movzwl %r13w,%eax
   553f9:	48 83 c0 0d          	add    $0xd,%rax
   553fd:	4d 85 c0             	test   %r8,%r8
   55400:	40 0f 95 c5          	setne  %bpl
   55404:	bb 08 00 00 00       	mov    $0x8,%ebx
   55409:	48 0f 45 d8          	cmovne %rax,%rbx
   5540d:	4c 01 f3             	add    %r14,%rbx
   55410:	48 81 fb 70 1e 00 00 	cmp    $0x1e70,%rbx
   55417:	76 07                	jbe    55420 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xe0>
   55419:	31 c0                	xor    %eax,%eax
   5541b:	e9 bf 09 00 00       	jmp    55ddf <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa9f>
   55420:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55427:	00 
   55428:	4c 8d 63 24          	lea    0x24(%rbx),%r12
   5542c:	49 c7 42 10 00 00 00 	movq   $0x0,0x10(%r10)
   55433:	00 
   55434:	49 8b 02             	mov    (%r10),%rax
   55437:	49 39 c4             	cmp    %rax,%r12
   5543a:	89 b4 24 fc 00 00 00 	mov    %esi,0xfc(%rsp)
   55441:	48 89 bc 24 98 01 00 	mov    %rdi,0x198(%rsp)
   55448:	00 
   55449:	4c 89 4c 24 10       	mov    %r9,0x10(%rsp)
   5544e:	4c 89 44 24 18       	mov    %r8,0x18(%rsp)
   55453:	0f 87 98 09 00 00    	ja     55df1 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xab1>
   55459:	45 31 ff             	xor    %r15d,%r15d
   5545c:	0f cb                	bswap  %ebx
   5545e:	4c 29 f8             	sub    %r15,%rax
   55461:	48 83 f8 03          	cmp    $0x3,%rax
   55465:	0f 86 eb 09 00 00    	jbe    55e56 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xb16>
   5546b:	49 8b 42 08          	mov    0x8(%r10),%rax
   5546f:	42 89 1c 38          	mov    %ebx,(%rax,%r15,1)
   55473:	49 8d 47 04          	lea    0x4(%r15),%rax
   55477:	49 89 42 10          	mov    %rax,0x10(%r10)
   5547b:	49 3b 02             	cmp    (%r10),%rax
   5547e:	75 27                	jne    554a7 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x167>
   55480:	4c 89 d7             	mov    %r10,%rdi
   55483:	41 89 cc             	mov    %ecx,%r12d
   55486:	48 89 d3             	mov    %rdx,%rbx
   55489:	67 e8 81 7a ff ff    	addr32 call 4cf10 <_RNvMs4_NtCsgFX3jaOk65H_5alloc7raw_vecINtB5_6RawVechE8grow_oneB7_>
   5548f:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55496:	00 
   55497:	48 89 da             	mov    %rbx,%rdx
   5549a:	44 89 e1             	mov    %r12d,%ecx
   5549d:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
   554a2:	4c 8b 4c 24 10       	mov    0x10(%rsp),%r9
   554a7:	49 8b 42 08          	mov    0x8(%r10),%rax
   554ab:	42 88 54 38 04       	mov    %dl,0x4(%rax,%r15,1)
   554b0:	49 8d 47 05          	lea    0x5(%r15),%rax
   554b4:	49 89 42 10          	mov    %rax,0x10(%r10)
   554b8:	49 3b 02             	cmp    (%r10),%rax
   554bb:	75 1f                	jne    554dc <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x19c>
   554bd:	4c 89 d7             	mov    %r10,%rdi
   554c0:	89 cb                	mov    %ecx,%ebx
   554c2:	67 e8 48 7a ff ff    	addr32 call 4cf10 <_RNvMs4_NtCsgFX3jaOk65H_5alloc7raw_vecINtB5_6RawVechE8grow_oneB7_>
   554c8:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   554cf:	00 
   554d0:	89 d9                	mov    %ebx,%ecx
   554d2:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
   554d7:	4c 8b 4c 24 10       	mov    0x10(%rsp),%r9
   554dc:	49 8b 42 08          	mov    0x8(%r10),%rax
   554e0:	42 88 6c 38 05       	mov    %bpl,0x5(%rax,%r15,1)
   554e5:	49 83 c7 06          	add    $0x6,%r15
   554e9:	4d 89 7a 10          	mov    %r15,0x10(%r10)
   554ed:	0f c9                	bswap  %ecx
   554ef:	49 8b 02             	mov    (%r10),%rax
   554f2:	4c 29 f8             	sub    %r15,%rax
   554f5:	48 83 f8 03          	cmp    $0x3,%rax
   554f9:	0f 86 8e 09 00 00    	jbe    55e8d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xb4d>
   554ff:	45 89 f4             	mov    %r14d,%r12d
   55502:	49 8d 47 04          	lea    0x4(%r15),%rax
   55506:	48 bd 00 00 00 00 00 	movabs $0x8000000000000000,%rbp
   5550d:	00 00 80 
   55510:	49 8b 52 08          	mov    0x8(%r10),%rdx
   55514:	42 89 0c 3a          	mov    %ecx,(%rdx,%r15,1)
   55518:	49 89 42 10          	mov    %rax,0x10(%r10)
   5551c:	4d 85 c0             	test   %r8,%r8
   5551f:	0f 84 ea 00 00 00    	je     5560f <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x2cf>
   55525:	49 3b 02             	cmp    (%r10),%rax
   55528:	75 16                	jne    55540 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x200>
   5552a:	4c 89 d7             	mov    %r10,%rdi
   5552d:	67 e8 dd 79 ff ff    	addr32 call 4cf10 <_RNvMs4_NtCsgFX3jaOk65H_5alloc7raw_vecINtB5_6RawVechE8grow_oneB7_>
   55533:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   5553a:	00 
   5553b:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
   55540:	49 8b 42 08          	mov    0x8(%r10),%rax
   55544:	0f b6 4c 24 0f       	movzbl 0xf(%rsp),%ecx
   55549:	42 88 4c 38 04       	mov    %cl,0x4(%rax,%r15,1)
   5554e:	49 83 c7 05          	add    $0x5,%r15
   55552:	66 41 c1 c5 08       	rol    $0x8,%r13w
   55557:	4d 89 7a 10          	mov    %r15,0x10(%r10)
   5555b:	49 8b 02             	mov    (%r10),%rax
   5555e:	4c 29 f8             	sub    %r15,%rax
   55561:	48 83 f8 01          	cmp    $0x1,%rax
   55565:	0f 86 ce 09 00 00    	jbe    55f39 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xbf9>
   5556b:	49 8b 42 08          	mov    0x8(%r10),%rax
   5556f:	66 46 89 2c 38       	mov    %r13w,(%rax,%r15,1)
   55574:	49 83 c7 02          	add    $0x2,%r15
   55578:	41 0f b7 58 18       	movzwl 0x18(%r8),%ebx
   5557d:	66 c1 c3 08          	rol    $0x8,%bx
   55581:	4d 89 7a 10          	mov    %r15,0x10(%r10)
   55585:	49 8b 02             	mov    (%r10),%rax
   55588:	4c 29 f8             	sub    %r15,%rax
   5558b:	48 83 f8 01          	cmp    $0x1,%rax
   5558f:	0f 86 ca 09 00 00    	jbe    55f5f <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xc1f>
   55595:	49 8b 42 08          	mov    0x8(%r10),%rax
   55599:	66 42 89 1c 38       	mov    %bx,(%rax,%r15,1)
   5559e:	49 83 c7 02          	add    $0x2,%r15
   555a2:	4d 89 7a 10          	mov    %r15,0x10(%r10)
   555a6:	49 8b 00             	mov    (%r8),%rax
   555a9:	48 89 c1             	mov    %rax,%rcx
   555ac:	48 31 e9             	xor    %rbp,%rcx
   555af:	48 85 c0             	test   %rax,%rax
   555b2:	b8 01 00 00 00       	mov    $0x1,%eax
   555b7:	48 0f 48 c1          	cmovs  %rcx,%rax
   555bb:	48 85 c0             	test   %rax,%rax
   555be:	74 17                	je     555d7 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x297>
   555c0:	48 83 f8 01          	cmp    $0x1,%rax
   555c4:	75 28                	jne    555ee <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x2ae>
   555c6:	49 8b 70 08          	mov    0x8(%r8),%rsi
   555ca:	49 8b 50 10          	mov    0x10(%r8),%rdx
   555ce:	eb 19                	jmp    555e9 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x2a9>
   555d0:	b0 06                	mov    $0x6,%al
   555d2:	e9 08 08 00 00       	jmp    55ddf <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa9f>
   555d7:	41 8b 40 08          	mov    0x8(%r8),%eax
   555db:	89 44 24 20          	mov    %eax,0x20(%rsp)
   555df:	48 8d 74 24 20       	lea    0x20(%rsp),%rsi
   555e4:	ba 04 00 00 00       	mov    $0x4,%edx
   555e9:	4c 89 d7             	mov    %r10,%rdi
   555ec:	eb 0f                	jmp    555fd <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x2bd>
   555ee:	49 83 c0 08          	add    $0x8,%r8
   555f2:	ba 10 00 00 00       	mov    $0x10,%edx
   555f7:	4c 89 d7             	mov    %r10,%rdi
   555fa:	4c 89 c6             	mov    %r8,%rsi
   555fd:	e8 de f1 ff ff       	call   547e0 <_RNvMs_NtCsgFX3jaOk65H_5alloc3vecINtB4_3VechE15append_elementsCsHnFHAC5PMO_12rust_reality>
   55602:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55609:	00 
   5560a:	4c 8b 4c 24 10       	mov    0x10(%rsp),%r9
   5560f:	66 41 c1 c4 08       	rol    $0x8,%r12w
   55614:	49 8b 02             	mov    (%r10),%rax
   55617:	4d 8b 7a 10          	mov    0x10(%r10),%r15
   5561b:	4c 29 f8             	sub    %r15,%rax
   5561e:	48 83 f8 01          	cmp    $0x1,%rax
   55622:	0f 86 94 08 00 00    	jbe    55ebc <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xb7c>
   55628:	49 8b 42 08          	mov    0x8(%r10),%rax
   5562c:	66 46 89 24 38       	mov    %r12w,(%rax,%r15,1)
   55631:	49 83 c7 02          	add    $0x2,%r15
   55635:	4d 89 7a 10          	mov    %r15,0x10(%r10)
   55639:	49 8b 02             	mov    (%r10),%rax
   5563c:	4c 29 f8             	sub    %r15,%rax
   5563f:	49 39 c6             	cmp    %rax,%r14
   55642:	0f 87 9a 08 00 00    	ja     55ee2 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xba2>
   55648:	4d 85 f6             	test   %r14,%r14
   5564b:	74 1b                	je     55668 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x328>
   5564d:	49 8b 7a 08          	mov    0x8(%r10),%rdi
   55651:	4c 01 ff             	add    %r15,%rdi
   55654:	4c 89 ce             	mov    %r9,%rsi
   55657:	4c 89 f2             	mov    %r14,%rdx
   5565a:	ff 15 50 6d 00 00    	call   *0x6d50(%rip)        # 5c3b0 <memcpy@GLIBC_2.14>
   55660:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55667:	00 
   55668:	4d 01 f7             	add    %r14,%r15
   5566b:	4d 89 7a 10          	mov    %r15,0x10(%r10)
   5566f:	49 83 ff 04          	cmp    $0x4,%r15
   55673:	0f 82 8d 08 00 00    	jb     55f06 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xbc6>
   55679:	4d 8b 72 08          	mov    0x8(%r10),%r14
   5567d:	0f 57 c0             	xorps  %xmm0,%xmm0
   55680:	0f 29 44 24 50       	movaps %xmm0,0x50(%rsp)
   55685:	0f 29 44 24 40       	movaps %xmm0,0x40(%rsp)
   5568a:	48 8b 84 24 98 01 00 	mov    0x198(%rsp),%rax
   55691:	00 
   55692:	0f 10 08             	movups (%rax),%xmm1
   55695:	0f 10 50 10          	movups 0x10(%rax),%xmm2
   55699:	0f 29 94 24 10 01 00 	movaps %xmm2,0x110(%rsp)
   556a0:	00 
   556a1:	0f 29 8c 24 00 01 00 	movaps %xmm1,0x100(%rsp)
   556a8:	00 
   556a9:	0f 29 84 24 20 01 00 	movaps %xmm0,0x120(%rsp)
   556b0:	00 
   556b1:	0f 29 84 24 30 01 00 	movaps %xmm0,0x130(%rsp)
   556b8:	00 
   556b9:	0f 28 05 80 fd fa ff 	movaps -0x50280(%rip),%xmm0        # 5440 <__abi_tag+0x5144>
   556c0:	0f 57 c8             	xorps  %xmm0,%xmm1
   556c3:	0f 57 d0             	xorps  %xmm0,%xmm2
   556c6:	0f 29 8c 24 00 01 00 	movaps %xmm1,0x100(%rsp)
   556cd:	00 
   556ce:	0f 29 94 24 10 01 00 	movaps %xmm2,0x110(%rsp)
   556d5:	00 
   556d6:	0f 29 84 24 20 01 00 	movaps %xmm0,0x120(%rsp)
   556dd:	00 
   556de:	0f 29 84 24 30 01 00 	movaps %xmm0,0x130(%rsp)
   556e5:	00 
   556e6:	0f 10 05 23 18 fb ff 	movups -0x4e7dd(%rip),%xmm0        # 6f10 <__abi_tag+0x6c14>
   556ed:	0f 29 84 24 b0 01 00 	movaps %xmm0,0x1b0(%rsp)
   556f4:	00 
   556f5:	0f 10 05 04 18 fb ff 	movups -0x4e7fc(%rip),%xmm0        # 6f00 <__abi_tag+0x6c04>
   556fc:	0f 29 84 24 a0 01 00 	movaps %xmm0,0x1a0(%rsp)
   55703:	00 
   55704:	48 c7 84 24 c0 01 00 	movq   $0x1,0x1c0(%rsp)
   5570b:	00 01 00 00 00 
   55710:	48 8d 1d 79 09 00 00 	lea    0x979(%rip),%rbx        # 56090 <_RNvNtCsf16BXcWIZfP_4sha26sha25611compress256>
   55717:	48 8d bc 24 a0 01 00 	lea    0x1a0(%rsp),%rdi
   5571e:	00 
   5571f:	48 8d ac 24 00 01 00 	lea    0x100(%rsp),%rbp
   55726:	00 
   55727:	ba 01 00 00 00       	mov    $0x1,%edx
   5572c:	48 89 ee             	mov    %rbp,%rsi
   5572f:	ff d3                	call   *%rbx
   55731:	0f 28 05 78 fc fa ff 	movaps -0x50388(%rip),%xmm0        # 53b0 <__abi_tag+0x50b4>
   55738:	0f 28 8c 24 00 01 00 	movaps 0x100(%rsp),%xmm1
   5573f:	00 
   55740:	0f 57 c8             	xorps  %xmm0,%xmm1
   55743:	0f 28 94 24 10 01 00 	movaps 0x110(%rsp),%xmm2
   5574a:	00 
   5574b:	0f 57 d0             	xorps  %xmm0,%xmm2
   5574e:	0f 29 8c 24 00 01 00 	movaps %xmm1,0x100(%rsp)
   55755:	00 
   55756:	0f 29 94 24 10 01 00 	movaps %xmm2,0x110(%rsp)
   5575d:	00 
   5575e:	0f 28 8c 24 20 01 00 	movaps 0x120(%rsp),%xmm1
   55765:	00 
   55766:	0f 57 c8             	xorps  %xmm0,%xmm1
   55769:	0f 57 84 24 30 01 00 	xorps  0x130(%rsp),%xmm0
   55770:	00 
   55771:	0f 29 8c 24 20 01 00 	movaps %xmm1,0x120(%rsp)
   55778:	00 
   55779:	0f 29 84 24 30 01 00 	movaps %xmm0,0x130(%rsp)
   55780:	00 
   55781:	4d 8d 67 fc          	lea    -0x4(%r15),%r12
   55785:	4d 8d 6e 04          	lea    0x4(%r14),%r13
   55789:	0f 10 05 80 17 fb ff 	movups -0x4e880(%rip),%xmm0        # 6f10 <__abi_tag+0x6c14>
   55790:	0f 29 84 24 c0 00 00 	movaps %xmm0,0xc0(%rsp)
   55797:	00 
   55798:	0f 10 05 61 17 fb ff 	movups -0x4e89f(%rip),%xmm0        # 6f00 <__abi_tag+0x6c04>
   5579f:	0f 29 84 24 b0 00 00 	movaps %xmm0,0xb0(%rsp)
   557a6:	00 
   557a7:	48 c7 84 24 d0 00 00 	movq   $0x1,0xd0(%rsp)
   557ae:	00 01 00 00 00 
   557b3:	48 8d bc 24 b0 00 00 	lea    0xb0(%rsp),%rdi
   557ba:	00 
   557bb:	ba 01 00 00 00       	mov    $0x1,%edx
   557c0:	48 89 ee             	mov    %rbp,%rsi
   557c3:	ff d3                	call   *%rbx
   557c5:	48 8b 84 24 d0 00 00 	mov    0xd0(%rsp),%rax
   557cc:	00 
   557cd:	48 89 44 24 68       	mov    %rax,0x68(%rsp)
   557d2:	0f 28 84 24 b0 00 00 	movaps 0xb0(%rsp),%xmm0
   557d9:	00 
   557da:	0f 28 8c 24 c0 00 00 	movaps 0xc0(%rsp),%xmm1
   557e1:	00 
   557e2:	0f 11 4c 24 58       	movups %xmm1,0x58(%rsp)
   557e7:	0f 11 44 24 48       	movups %xmm0,0x48(%rsp)
   557ec:	48 8b 84 24 c0 01 00 	mov    0x1c0(%rsp),%rax
   557f3:	00 
   557f4:	48 89 44 24 40       	mov    %rax,0x40(%rsp)
   557f9:	0f 28 84 24 a0 01 00 	movaps 0x1a0(%rsp),%xmm0
   55800:	00 
   55801:	0f 28 8c 24 b0 01 00 	movaps 0x1b0(%rsp),%xmm1
   55808:	00 
   55809:	0f 29 4c 24 30       	movaps %xmm1,0x30(%rsp)
   5580e:	0f 29 44 24 20       	movaps %xmm0,0x20(%rsp)
   55813:	0f 29 84 24 40 01 00 	movaps %xmm0,0x140(%rsp)
   5581a:	00 
   5581b:	0f 29 8c 24 50 01 00 	movaps %xmm1,0x150(%rsp)
   55822:	00 
   55823:	48 8b 44 24 40       	mov    0x40(%rsp),%rax
   55828:	48 89 84 24 60 01 00 	mov    %rax,0x160(%rsp)
   5582f:	00 
   55830:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
   55835:	48 89 84 24 68 01 00 	mov    %rax,0x168(%rsp)
   5583c:	00 
   5583d:	0f 28 44 24 50       	movaps 0x50(%rsp),%xmm0
   55842:	0f 29 84 24 70 01 00 	movaps %xmm0,0x170(%rsp)
   55849:	00 
   5584a:	0f 28 44 24 60       	movaps 0x60(%rsp),%xmm0
   5584f:	0f 29 84 24 80 01 00 	movaps %xmm0,0x180(%rsp)
   55856:	00 
   55857:	0f 10 05 bb 13 fb ff 	movups -0x4ec45(%rip),%xmm0        # 6c19 <__abi_tag+0x691d>
   5585e:	0f 29 84 24 10 01 00 	movaps %xmm0,0x110(%rsp)
   55865:	00 
   55866:	0f 10 05 9c 13 fb ff 	movups -0x4ec64(%rip),%xmm0        # 6c09 <__abi_tag+0x690d>
   5586d:	0f 29 84 24 00 01 00 	movaps %xmm0,0x100(%rsp)
   55874:	00 
   55875:	66 c7 84 24 20 01 00 	movw   $0x63,0x120(%rsp)
   5587c:	00 63 00 
   5587f:	8b 84 24 fc 00 00 00 	mov    0xfc(%rsp),%eax
   55886:	88 84 24 22 01 00 00 	mov    %al,0x122(%rsp)
   5588d:	49 83 fc 1c          	cmp    $0x1c,%r12
   55891:	77 25                	ja     558b8 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x578>
   55893:	48 8d bc 24 23 01 00 	lea    0x123(%rsp),%rdi
   5589a:	00 
   5589b:	4c 89 ee             	mov    %r13,%rsi
   5589e:	4c 89 e2             	mov    %r12,%rdx
   558a1:	ff 15 09 6b 00 00    	call   *0x6b09(%rip)        # 5c3b0 <memcpy@GLIBC_2.14>
   558a7:	41 80 c4 23          	add    $0x23,%r12b
   558ab:	44 88 a4 24 3f 01 00 	mov    %r12b,0x13f(%rsp)
   558b2:	00 
   558b3:	e9 a9 00 00 00       	jmp    55961 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x621>
   558b8:	4c 8d a4 24 40 01 00 	lea    0x140(%rsp),%r12
   558bf:	00 
   558c0:	49 83 c7 df          	add    $0xffffffffffffffdf,%r15
   558c4:	41 0f 10 45 00       	movups 0x0(%r13),%xmm0
   558c9:	41 0f 10 4d 0d       	movups 0xd(%r13),%xmm1
   558ce:	0f 11 8c 24 30 01 00 	movups %xmm1,0x130(%rsp)
   558d5:	00 
   558d6:	0f 11 84 24 23 01 00 	movups %xmm0,0x123(%rsp)
   558dd:	00 
   558de:	48 ff 84 24 60 01 00 	incq   0x160(%rsp)
   558e5:	00 
   558e6:	48 8d b4 24 00 01 00 	lea    0x100(%rsp),%rsi
   558ed:	00 
   558ee:	ba 01 00 00 00       	mov    $0x1,%edx
   558f3:	4c 89 e7             	mov    %r12,%rdi
   558f6:	67 e8 94 07 00 00    	addr32 call 56090 <_RNvNtCsf16BXcWIZfP_4sha26sha25611compress256>
   558fc:	c6 84 24 3f 01 00 00 	movb   $0x0,0x13f(%rsp)
   55903:	00 
   55904:	4c 89 fa             	mov    %r15,%rdx
   55907:	48 c1 ea 06          	shr    $0x6,%rdx
   5590b:	48 b8 00 00 00 00 00 	movabs $0x8000000000000000,%rax
   55912:	00 00 80 
   55915:	48 83 c0 c0          	add    $0xffffffffffffffc0,%rax
   55919:	4c 21 f8             	and    %r15,%rax
   5591c:	41 83 e7 3f          	and    $0x3f,%r15d
   55920:	4d 8d 2c 06          	lea    (%r14,%rax,1),%r13
   55924:	49 83 c5 21          	add    $0x21,%r13
   55928:	48 85 d2             	test   %rdx,%rdx
   5592b:	74 18                	je     55945 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x605>
   5592d:	49 83 c6 21          	add    $0x21,%r14
   55931:	48 01 94 24 60 01 00 	add    %rdx,0x160(%rsp)
   55938:	00 
   55939:	4c 89 e7             	mov    %r12,%rdi
   5593c:	4c 89 f6             	mov    %r14,%rsi
   5593f:	67 e8 4b 07 00 00    	addr32 call 56090 <_RNvNtCsf16BXcWIZfP_4sha26sha25611compress256>
   55945:	44 88 bc 24 3f 01 00 	mov    %r15b,0x13f(%rsp)
   5594c:	00 
   5594d:	48 8d bc 24 00 01 00 	lea    0x100(%rsp),%rdi
   55954:	00 
   55955:	4c 89 ee             	mov    %r13,%rsi
   55958:	4c 89 fa             	mov    %r15,%rdx
   5595b:	ff 15 4f 6a 00 00    	call   *0x6a4f(%rip)        # 5c3b0 <memcpy@GLIBC_2.14>
   55961:	48 8d 7c 24 20       	lea    0x20(%rsp),%rdi
   55966:	48 8d b4 24 00 01 00 	lea    0x100(%rsp),%rsi
   5596d:	00 
   5596e:	ba 90 00 00 00       	mov    $0x90,%edx
   55973:	ff 15 37 6a 00 00    	call   *0x6a37(%rip)        # 5c3b0 <memcpy@GLIBC_2.14>
   55979:	4c 8d 74 24 60       	lea    0x60(%rsp),%r14
   5597e:	0f b6 5c 24 5f       	movzbl 0x5f(%rsp),%ebx
   55983:	4c 8b a4 24 80 00 00 	mov    0x80(%rsp),%r12
   5598a:	00 
   5598b:	49 89 df             	mov    %rbx,%r15
   5598e:	49 83 f7 3f          	xor    $0x3f,%r15
   55992:	c6 44 1c 20 80       	movb   $0x80,0x20(%rsp,%rbx,1)
   55997:	48 8d 3c 1c          	lea    (%rsp,%rbx,1),%rdi
   5599b:	48 83 c7 21          	add    $0x21,%rdi
   5599f:	31 f6                	xor    %esi,%esi
   559a1:	4c 89 fa             	mov    %r15,%rdx
   559a4:	ff 15 86 66 00 00    	call   *0x6686(%rip)        # 5c030 <memset@GLIBC_2.2.5>
   559aa:	49 83 ff 07          	cmp    $0x7,%r15
   559ae:	77 67                	ja     55a17 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x6d7>
   559b0:	0f 28 44 24 20       	movaps 0x20(%rsp),%xmm0
   559b5:	0f 28 4c 24 30       	movaps 0x30(%rsp),%xmm1
   559ba:	0f 28 54 24 40       	movaps 0x40(%rsp),%xmm2
   559bf:	66 0f 6f 5c 24 50    	movdqa 0x50(%rsp),%xmm3
   559c5:	66 0f 7f 9c 24 e0 00 	movdqa %xmm3,0xe0(%rsp)
   559cc:	00 00 
   559ce:	0f 29 94 24 d0 00 00 	movaps %xmm2,0xd0(%rsp)
   559d5:	00 
   559d6:	0f 29 8c 24 c0 00 00 	movaps %xmm1,0xc0(%rsp)
   559dd:	00 
   559de:	0f 29 84 24 b0 00 00 	movaps %xmm0,0xb0(%rsp)
   559e5:	00 
   559e6:	48 8d b4 24 b0 00 00 	lea    0xb0(%rsp),%rsi
   559ed:	00 
   559ee:	ba 01 00 00 00       	mov    $0x1,%edx
   559f3:	4c 89 f7             	mov    %r14,%rdi
   559f6:	67 e8 94 06 00 00    	addr32 call 56090 <_RNvNtCsf16BXcWIZfP_4sha26sha25611compress256>
   559fc:	0f 57 c0             	xorps  %xmm0,%xmm0
   559ff:	0f 29 44 24 20       	movaps %xmm0,0x20(%rsp)
   55a04:	0f 29 44 24 30       	movaps %xmm0,0x30(%rsp)
   55a09:	0f 29 44 24 40       	movaps %xmm0,0x40(%rsp)
   55a0e:	48 c7 44 24 50 00 00 	movq   $0x0,0x50(%rsp)
   55a15:	00 00 
   55a17:	49 c1 e4 09          	shl    $0x9,%r12
   55a1b:	c1 e3 03             	shl    $0x3,%ebx
   55a1e:	4c 09 e3             	or     %r12,%rbx
   55a21:	48 0f cb             	bswap  %rbx
   55a24:	48 89 5c 24 58       	mov    %rbx,0x58(%rsp)
   55a29:	48 8b 44 24 50       	mov    0x50(%rsp),%rax
   55a2e:	48 89 84 24 e0 00 00 	mov    %rax,0xe0(%rsp)
   55a35:	00 
   55a36:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
   55a3b:	48 89 84 24 e8 00 00 	mov    %rax,0xe8(%rsp)
   55a42:	00 
   55a43:	0f 28 44 24 20       	movaps 0x20(%rsp),%xmm0
   55a48:	0f 28 4c 24 30       	movaps 0x30(%rsp),%xmm1
   55a4d:	0f 28 54 24 40       	movaps 0x40(%rsp),%xmm2
   55a52:	0f 29 94 24 d0 00 00 	movaps %xmm2,0xd0(%rsp)
   55a59:	00 
   55a5a:	0f 29 8c 24 c0 00 00 	movaps %xmm1,0xc0(%rsp)
   55a61:	00 
   55a62:	0f 29 84 24 b0 00 00 	movaps %xmm0,0xb0(%rsp)
   55a69:	00 
   55a6a:	48 8d b4 24 b0 00 00 	lea    0xb0(%rsp),%rsi
   55a71:	00 
   55a72:	ba 01 00 00 00       	mov    $0x1,%edx
   55a77:	4c 89 f7             	mov    %r14,%rdi
   55a7a:	48 8d 1d 0f 06 00 00 	lea    0x60f(%rip),%rbx        # 56090 <_RNvNtCsf16BXcWIZfP_4sha26sha25611compress256>
   55a81:	ff d3                	call   *%rbx
   55a83:	48 8d 6c 24 64       	lea    0x64(%rsp),%rbp
   55a88:	4c 8d 6c 24 68       	lea    0x68(%rsp),%r13
   55a8d:	4c 8d 64 24 6c       	lea    0x6c(%rsp),%r12
   55a92:	66 0f 6f 44 24 60    	movdqa 0x60(%rsp),%xmm0
   55a98:	66 0f 6f 4c 24 70    	movdqa 0x70(%rsp),%xmm1
   55a9e:	66 0f ef db          	pxor   %xmm3,%xmm3
   55aa2:	66 0f 6f d0          	movdqa %xmm0,%xmm2
   55aa6:	66 0f 68 d3          	punpckhbw %xmm3,%xmm2
   55aaa:	f2 0f 70 d2 1b       	pshuflw $0x1b,%xmm2,%xmm2
   55aaf:	f3 0f 70 d2 1b       	pshufhw $0x1b,%xmm2,%xmm2
   55ab4:	66 0f 60 c3          	punpcklbw %xmm3,%xmm0
   55ab8:	f2 0f 70 c0 1b       	pshuflw $0x1b,%xmm0,%xmm0
   55abd:	f3 0f 70 c0 1b       	pshufhw $0x1b,%xmm0,%xmm0
   55ac2:	66 0f 67 c2          	packuswb %xmm2,%xmm0
   55ac6:	66 0f 7f 44 24 20    	movdqa %xmm0,0x20(%rsp)
   55acc:	66 0f 6f d1          	movdqa %xmm1,%xmm2
   55ad0:	66 0f 68 d3          	punpckhbw %xmm3,%xmm2
   55ad4:	f2 0f 70 d2 1b       	pshuflw $0x1b,%xmm2,%xmm2
   55ad9:	f3 0f 70 d2 1b       	pshufhw $0x1b,%xmm2,%xmm2
   55ade:	66 0f 60 cb          	punpcklbw %xmm3,%xmm1
   55ae2:	f2 0f 70 c9 1b       	pshuflw $0x1b,%xmm1,%xmm1
   55ae7:	f3 0f 70 c9 1b       	pshufhw $0x1b,%xmm1,%xmm1
   55aec:	66 0f 67 ca          	packuswb %xmm2,%xmm1
   55af0:	66 0f 7f 4c 24 30    	movdqa %xmm1,0x30(%rsp)
   55af6:	48 8b 84 24 a8 00 00 	mov    0xa8(%rsp),%rax
   55afd:	00 
   55afe:	c6 44 24 40 80       	movb   $0x80,0x40(%rsp)
   55b03:	f3 0f 7f 5c 24 41    	movdqu %xmm3,0x41(%rsp)
   55b09:	48 c7 44 24 50 00 00 	movq   $0x0,0x50(%rsp)
   55b10:	00 00 
   55b12:	4c 8d bc 24 88 00 00 	lea    0x88(%rsp),%r15
   55b19:	00 
   55b1a:	48 c1 e0 09          	shl    $0x9,%rax
   55b1e:	48 0d 00 01 00 00    	or     $0x100,%rax
   55b24:	48 0f c8             	bswap  %rax
   55b27:	48 89 44 24 58       	mov    %rax,0x58(%rsp)
   55b2c:	48 8b 44 24 50       	mov    0x50(%rsp),%rax
   55b31:	48 89 84 24 e0 00 00 	mov    %rax,0xe0(%rsp)
   55b38:	00 
   55b39:	48 8b 44 24 58       	mov    0x58(%rsp),%rax
   55b3e:	48 89 84 24 e8 00 00 	mov    %rax,0xe8(%rsp)
   55b45:	00 
   55b46:	0f b6 44 24 40       	movzbl 0x40(%rsp),%eax
   55b4b:	88 84 24 d0 00 00 00 	mov    %al,0xd0(%rsp)
   55b52:	48 8b 44 24 41       	mov    0x41(%rsp),%rax
   55b57:	48 89 84 24 d1 00 00 	mov    %rax,0xd1(%rsp)
   55b5e:	00 
   55b5f:	8b 44 24 49          	mov    0x49(%rsp),%eax
   55b63:	89 84 24 d9 00 00 00 	mov    %eax,0xd9(%rsp)
   55b6a:	0f b7 44 24 4d       	movzwl 0x4d(%rsp),%eax
   55b6f:	66 89 84 24 dd 00 00 	mov    %ax,0xdd(%rsp)
   55b76:	00 
   55b77:	0f b6 44 24 4f       	movzbl 0x4f(%rsp),%eax
   55b7c:	88 84 24 df 00 00 00 	mov    %al,0xdf(%rsp)
   55b83:	66 0f 7f 8c 24 c0 00 	movdqa %xmm1,0xc0(%rsp)
   55b8a:	00 00 
   55b8c:	66 0f 7f 84 24 b0 00 	movdqa %xmm0,0xb0(%rsp)
   55b93:	00 00 
   55b95:	48 8d b4 24 b0 00 00 	lea    0xb0(%rsp),%rsi
   55b9c:	00 
   55b9d:	ba 01 00 00 00       	mov    $0x1,%edx
   55ba2:	4c 89 ff             	mov    %r15,%rdi
   55ba5:	ff d3                	call   *%rbx
   55ba7:	c6 44 24 5f 00       	movb   $0x0,0x5f(%rsp)
   55bac:	c7 44 24 60 00 00 00 	movl   $0x0,0x60(%rsp)
   55bb3:	00 
   55bb4:	f3 0f 6f 8c 24 88 00 	movdqu 0x88(%rsp),%xmm1
   55bbb:	00 00 
   55bbd:	f3 0f 6f 84 24 98 00 	movdqu 0x98(%rsp),%xmm0
   55bc4:	00 00 
   55bc6:	c7 44 24 64 00 00 00 	movl   $0x0,0x64(%rsp)
   55bcd:	00 
   55bce:	c7 44 24 68 00 00 00 	movl   $0x0,0x68(%rsp)
   55bd5:	00 
   55bd6:	c7 44 24 6c 00 00 00 	movl   $0x0,0x6c(%rsp)
   55bdd:	00 
   55bde:	c7 44 24 70 00 00 00 	movl   $0x0,0x70(%rsp)
   55be5:	00 
   55be6:	48 8d 44 24 70       	lea    0x70(%rsp),%rax
   55beb:	c7 44 24 74 00 00 00 	movl   $0x0,0x74(%rsp)
   55bf2:	00 
   55bf3:	48 8d 44 24 74       	lea    0x74(%rsp),%rax
   55bf8:	c7 44 24 78 00 00 00 	movl   $0x0,0x78(%rsp)
   55bff:	00 
   55c00:	48 8d 44 24 78       	lea    0x78(%rsp),%rax
   55c05:	c7 44 24 7c 00 00 00 	movl   $0x0,0x7c(%rsp)
   55c0c:	00 
   55c0d:	48 8d 44 24 7c       	lea    0x7c(%rsp),%rax
   55c12:	48 c7 84 24 80 00 00 	movq   $0x0,0x80(%rsp)
   55c19:	00 00 00 00 00 
   55c1e:	48 8d 84 24 80 00 00 	lea    0x80(%rsp),%rax
   55c25:	00 
   55c26:	c7 84 24 88 00 00 00 	movl   $0x0,0x88(%rsp)
   55c2d:	00 00 00 00 
   55c31:	48 8d 84 24 8c 00 00 	lea    0x8c(%rsp),%rax
   55c38:	00 
   55c39:	c7 84 24 8c 00 00 00 	movl   $0x0,0x8c(%rsp)
   55c40:	00 00 00 00 
   55c44:	48 8d 84 24 90 00 00 	lea    0x90(%rsp),%rax
   55c4b:	00 
   55c4c:	c7 84 24 90 00 00 00 	movl   $0x0,0x90(%rsp)
   55c53:	00 00 00 00 
   55c57:	48 8d 84 24 94 00 00 	lea    0x94(%rsp),%rax
   55c5e:	00 
   55c5f:	c7 84 24 94 00 00 00 	movl   $0x0,0x94(%rsp)
   55c66:	00 00 00 00 
   55c6a:	48 8d 84 24 98 00 00 	lea    0x98(%rsp),%rax
   55c71:	00 
   55c72:	c7 84 24 98 00 00 00 	movl   $0x0,0x98(%rsp)
   55c79:	00 00 00 00 
   55c7d:	48 8d 84 24 9c 00 00 	lea    0x9c(%rsp),%rax
   55c84:	00 
   55c85:	c7 84 24 9c 00 00 00 	movl   $0x0,0x9c(%rsp)
   55c8c:	00 00 00 00 
   55c90:	48 8d 84 24 a0 00 00 	lea    0xa0(%rsp),%rax
   55c97:	00 
   55c98:	c7 84 24 a0 00 00 00 	movl   $0x0,0xa0(%rsp)
   55c9f:	00 00 00 00 
   55ca3:	48 8d 84 24 a4 00 00 	lea    0xa4(%rsp),%rax
   55caa:	00 
   55cab:	c7 84 24 a4 00 00 00 	movl   $0x0,0xa4(%rsp)
   55cb2:	00 00 00 00 
   55cb6:	48 c7 84 24 a8 00 00 	movq   $0x0,0xa8(%rsp)
   55cbd:	00 00 00 00 00 
   55cc2:	48 8d 84 24 a8 00 00 	lea    0xa8(%rsp),%rax
   55cc9:	00 
   55cca:	66 0f ef d2          	pxor   %xmm2,%xmm2
   55cce:	66 0f 7f 94 24 b0 00 	movdqa %xmm2,0xb0(%rsp)
   55cd5:	00 00 
   55cd7:	66 0f 7f 94 24 c0 00 	movdqa %xmm2,0xc0(%rsp)
   55cde:	00 00 
   55ce0:	66 0f 7f 94 24 d0 00 	movdqa %xmm2,0xd0(%rsp)
   55ce7:	00 00 
   55ce9:	66 0f 7f 94 24 e0 00 	movdqa %xmm2,0xe0(%rsp)
   55cf0:	00 00 
   55cf2:	66 0f ef db          	pxor   %xmm3,%xmm3
   55cf6:	0f 28 94 24 b0 00 00 	movaps 0xb0(%rsp),%xmm2
   55cfd:	00 
   55cfe:	0f 29 54 24 20       	movaps %xmm2,0x20(%rsp)
   55d03:	0f 28 94 24 c0 00 00 	movaps 0xc0(%rsp),%xmm2
   55d0a:	00 
   55d0b:	0f 29 54 24 30       	movaps %xmm2,0x30(%rsp)
   55d10:	0f 28 94 24 d0 00 00 	movaps 0xd0(%rsp),%xmm2
   55d17:	00 
   55d18:	0f 29 54 24 40       	movaps %xmm2,0x40(%rsp)
   55d1d:	0f 28 94 24 e0 00 00 	movaps 0xe0(%rsp),%xmm2
   55d24:	00 
   55d25:	0f 29 54 24 50       	movaps %xmm2,0x50(%rsp)
   55d2a:	48 8d 44 24 20       	lea    0x20(%rsp),%rax
   55d2f:	66 0f 6f d1          	movdqa %xmm1,%xmm2
   55d33:	66 0f 68 d3          	punpckhbw %xmm3,%xmm2
   55d37:	f2 0f 70 d2 1b       	pshuflw $0x1b,%xmm2,%xmm2
   55d3c:	f3 0f 70 d2 1b       	pshufhw $0x1b,%xmm2,%xmm2
   55d41:	66 0f 60 cb          	punpcklbw %xmm3,%xmm1
   55d45:	f2 0f 70 c9 1b       	pshuflw $0x1b,%xmm1,%xmm1
   55d4a:	f3 0f 70 c9 1b       	pshufhw $0x1b,%xmm1,%xmm1
   55d4f:	66 0f 67 ca          	packuswb %xmm2,%xmm1
   55d53:	66 0f 6f d0          	movdqa %xmm0,%xmm2
   55d57:	66 0f 68 d3          	punpckhbw %xmm3,%xmm2
   55d5b:	f2 0f 70 d2 1b       	pshuflw $0x1b,%xmm2,%xmm2
   55d60:	f3 0f 70 d2 1b       	pshufhw $0x1b,%xmm2,%xmm2
   55d65:	66 0f 60 c3          	punpcklbw %xmm3,%xmm0
   55d69:	f2 0f 70 c0 1b       	pshuflw $0x1b,%xmm0,%xmm0
   55d6e:	f3 0f 70 c0 1b       	pshufhw $0x1b,%xmm0,%xmm0
   55d73:	66 0f 67 c2          	packuswb %xmm2,%xmm0
   55d77:	66 0f 7f 8c 24 b0 00 	movdqa %xmm1,0xb0(%rsp)
   55d7e:	00 00 
   55d80:	66 0f 7f 84 24 c0 00 	movdqa %xmm0,0xc0(%rsp)
   55d87:	00 00 
   55d89:	66 0f 7f 4c 24 20    	movdqa %xmm1,0x20(%rsp)
   55d8f:	66 0f 7f 44 24 30    	movdqa %xmm0,0x30(%rsp)
   55d95:	48 8d bc 24 b0 00 00 	lea    0xb0(%rsp),%rdi
   55d9c:	00 
   55d9d:	e8 9e de ff ff       	call   53c40 <_RINvNtCskADBYZwJmSU_4core3ptr9drop_glueINtNtCs2LyUJKmd2Yb_6digest3mac8CtOutputINtCsdqFEojVsrkx_4hmac4HmacNtCsf16BXcWIZfP_4sha26Sha256EEECsHnFHAC5PMO_12rust_reality>
   55da2:	48 8b bc 24 08 02 00 	mov    0x208(%rsp),%rdi
   55da9:	00 
   55daa:	48 8b 07             	mov    (%rdi),%rax
   55dad:	48 8b 77 10          	mov    0x10(%rdi),%rsi
   55db1:	48 29 f0             	sub    %rsi,%rax
   55db4:	48 83 f8 1f          	cmp    $0x1f,%rax
   55db8:	0f 86 60 01 00 00    	jbe    55f1e <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xbde>
   55dbe:	48 8b 47 08          	mov    0x8(%rdi),%rax
   55dc2:	0f 28 44 24 20       	movaps 0x20(%rsp),%xmm0
   55dc7:	0f 28 4c 24 30       	movaps 0x30(%rsp),%xmm1
   55dcc:	0f 11 4c 30 10       	movups %xmm1,0x10(%rax,%rsi,1)
   55dd1:	0f 11 04 30          	movups %xmm0,(%rax,%rsi,1)
   55dd5:	48 83 c6 20          	add    $0x20,%rsi
   55dd9:	48 89 77 10          	mov    %rsi,0x10(%rdi)
   55ddd:	b0 ff                	mov    $0xff,%al
   55ddf:	48 81 c4 c8 01 00 00 	add    $0x1c8,%rsp
   55de6:	5b                   	pop    %rbx
   55de7:	41 5c                	pop    %r12
   55de9:	41 5d                	pop    %r13
   55deb:	41 5e                	pop    %r14
   55ded:	41 5f                	pop    %r15
   55def:	5d                   	pop    %rbp
   55df0:	c3                   	ret
   55df1:	48 89 94 24 90 01 00 	mov    %rdx,0x190(%rsp)
   55df8:	00 
   55df9:	89 8c 24 f8 00 00 00 	mov    %ecx,0xf8(%rsp)
   55e00:	49 8b 52 08          	mov    0x8(%r10),%rdx
   55e04:	48 8d 7c 24 20       	lea    0x20(%rsp),%rdi
   55e09:	48 89 c6             	mov    %rax,%rsi
   55e0c:	4c 89 e1             	mov    %r12,%rcx
   55e0f:	4d 89 d7             	mov    %r10,%r15
   55e12:	e8 49 e9 ff ff       	call   54760 <_RNvMs5_NtCsgFX3jaOk65H_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsHnFHAC5PMO_12rust_reality>
   55e17:	80 7c 24 20 00       	cmpb   $0x0,0x20(%rsp)
   55e1c:	74 04                	je     55e22 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xae2>
   55e1e:	b0 09                	mov    $0x9,%al
   55e20:	eb bd                	jmp    55ddf <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa9f>
   55e22:	48 8b 44 24 28       	mov    0x28(%rsp),%rax
   55e27:	49 89 47 08          	mov    %rax,0x8(%r15)
   55e2b:	4d 89 27             	mov    %r12,(%r15)
   55e2e:	4d 89 fa             	mov    %r15,%r10
   55e31:	4d 8b 7f 10          	mov    0x10(%r15),%r15
   55e35:	4c 89 e0             	mov    %r12,%rax
   55e38:	4c 8b 4c 24 10       	mov    0x10(%rsp),%r9
   55e3d:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
   55e42:	8b 8c 24 f8 00 00 00 	mov    0xf8(%rsp),%ecx
   55e49:	48 8b 94 24 90 01 00 	mov    0x190(%rsp),%rdx
   55e50:	00 
   55e51:	e9 06 f6 ff ff       	jmp    5545c <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x11c>
   55e56:	49 89 d4             	mov    %rdx,%r12
   55e59:	ba 04 00 00 00       	mov    $0x4,%edx
   55e5e:	4c 89 d7             	mov    %r10,%rdi
   55e61:	4c 89 fe             	mov    %r15,%rsi
   55e64:	41 89 cf             	mov    %ecx,%r15d
   55e67:	e8 d4 de ff ff       	call   53d40 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55e6c:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55e73:	00 
   55e74:	4c 89 e2             	mov    %r12,%rdx
   55e77:	44 89 f9             	mov    %r15d,%ecx
   55e7a:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
   55e7f:	4c 8b 4c 24 10       	mov    0x10(%rsp),%r9
   55e84:	4d 8b 7a 10          	mov    0x10(%r10),%r15
   55e88:	e9 de f5 ff ff       	jmp    5546b <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x12b>
   55e8d:	ba 04 00 00 00       	mov    $0x4,%edx
   55e92:	4c 89 d7             	mov    %r10,%rdi
   55e95:	4c 89 fe             	mov    %r15,%rsi
   55e98:	89 cb                	mov    %ecx,%ebx
   55e9a:	e8 a1 de ff ff       	call   53d40 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55e9f:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55ea6:	00 
   55ea7:	89 d9                	mov    %ebx,%ecx
   55ea9:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
   55eae:	4c 8b 4c 24 10       	mov    0x10(%rsp),%r9
   55eb3:	4d 8b 7a 10          	mov    0x10(%r10),%r15
   55eb7:	e9 43 f6 ff ff       	jmp    554ff <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x1bf>
   55ebc:	ba 02 00 00 00       	mov    $0x2,%edx
   55ec1:	4c 89 d7             	mov    %r10,%rdi
   55ec4:	4c 89 fe             	mov    %r15,%rsi
   55ec7:	e8 74 de ff ff       	call   53d40 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55ecc:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55ed3:	00 
   55ed4:	4c 8b 4c 24 10       	mov    0x10(%rsp),%r9
   55ed9:	4d 8b 7a 10          	mov    0x10(%r10),%r15
   55edd:	e9 46 f7 ff ff       	jmp    55628 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x2e8>
   55ee2:	4c 89 d7             	mov    %r10,%rdi
   55ee5:	4c 89 fe             	mov    %r15,%rsi
   55ee8:	4c 89 f2             	mov    %r14,%rdx
   55eeb:	e8 50 de ff ff       	call   53d40 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55ef0:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55ef7:	00 
   55ef8:	4c 8b 4c 24 10       	mov    0x10(%rsp),%r9
   55efd:	4d 8b 7a 10          	mov    0x10(%r10),%r15
   55f01:	e9 47 f7 ff ff       	jmp    5564d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x30d>
   55f06:	48 8d 0d 8b 5e 00 00 	lea    0x5e8b(%rip),%rcx        # 5bd98 <__frame_dummy_init_array_entry+0x1fa8>
   55f0d:	bf 04 00 00 00       	mov    $0x4,%edi
   55f12:	4c 89 fe             	mov    %r15,%rsi
   55f15:	4c 89 fa             	mov    %r15,%rdx
   55f18:	67 e8 72 a5 ff ff    	addr32 call 50490 <_RNvNtNtCskADBYZwJmSU_4core5slice5index16slice_index_fail>
   55f1e:	ba 20 00 00 00       	mov    $0x20,%edx
   55f23:	e8 18 de ff ff       	call   53d40 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55f28:	48 8b bc 24 08 02 00 	mov    0x208(%rsp),%rdi
   55f2f:	00 
   55f30:	48 8b 77 10          	mov    0x10(%rdi),%rsi
   55f34:	e9 85 fe ff ff       	jmp    55dbe <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa7e>
   55f39:	ba 02 00 00 00       	mov    $0x2,%edx
   55f3e:	4c 89 d7             	mov    %r10,%rdi
   55f41:	4c 89 fe             	mov    %r15,%rsi
   55f44:	e8 f7 dd ff ff       	call   53d40 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55f49:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55f50:	00 
   55f51:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
   55f56:	4d 8b 7a 10          	mov    0x10(%r10),%r15
   55f5a:	e9 0c f6 ff ff       	jmp    5556b <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x22b>
   55f5f:	ba 02 00 00 00       	mov    $0x2,%edx
   55f64:	4c 89 d7             	mov    %r10,%rdi
   55f67:	4c 89 fe             	mov    %r15,%rsi
   55f6a:	e8 d1 dd ff ff       	call   53d40 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55f6f:	4c 8b 94 24 08 02 00 	mov    0x208(%rsp),%r10
   55f76:	00 
   55f77:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
   55f7c:	4d 8b 7a 10          	mov    0x10(%r10),%r15
   55f80:	e9 10 f6 ff ff       	jmp    55595 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x255>

Disassembly of section .init:

Disassembly of section .fini:

Disassembly of section .plt:
