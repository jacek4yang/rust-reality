
/home/jacek/.cache/rr-v230-official-candidate-75a1/rust-reality:     file format elf64-x86-64


Disassembly of section .text:

0000000000537030 <.text+0x357630>:
  537030:	55                   	push   %rbp
  537031:	41 57                	push   %r15
  537033:	41 56                	push   %r14
  537035:	41 55                	push   %r13
  537037:	41 54                	push   %r12
  537039:	53                   	push   %rbx
  53703a:	48 83 ec 28          	sub    $0x28,%rsp
  53703e:	49 89 cb             	mov    %rcx,%r11
  537041:	48 89 d3             	mov    %rdx,%rbx
  537044:	49 89 f5             	mov    %rsi,%r13
  537047:	49 89 fe             	mov    %rdi,%r14
  53704a:	0f b6 47 15          	movzbl 0x15(%rdi),%eax
  53704e:	3c 02                	cmp    $0x2,%al
  537050:	75 1c                	jne    53706e <__cxa_finalize@plt-0x2361d2>
  537052:	41 0f b6 7e 1b       	movzbl 0x1b(%r14),%edi
  537057:	45 0f b7 7e 16       	movzwl 0x16(%r14),%r15d
  53705c:	45 0f b7 66 18       	movzwl 0x18(%r14),%r12d
  537061:	41 0f b7 cf          	movzwl %r15w,%ecx
  537065:	41 0f b7 d4          	movzwl %r12w,%edx
  537069:	e9 ef 00 00 00       	jmp    53715d <__cxa_finalize@plt-0x2360e3>
  53706e:	41 0f b6 4e 1b       	movzbl 0x1b(%r14),%ecx
  537073:	89 4c 24 0c          	mov    %ecx,0xc(%rsp)
  537077:	c1 e1 04             	shl    $0x4,%ecx
  53707a:	41 0f b7 6e 16       	movzwl 0x16(%r14),%ebp
  53707f:	45 0f b7 7e 18       	movzwl 0x18(%r14),%r15d
  537084:	44 0f b7 d5          	movzwl %bp,%r10d
  537088:	41 0f b7 f7          	movzwl %r15w,%esi
  53708c:	4c 01 c1             	add    %r8,%rcx
  53708f:	4c 01 d1             	add    %r10,%rcx
  537092:	48 89 74 24 20       	mov    %rsi,0x20(%rsp)
  537097:	48 8d 3c 0e          	lea    (%rsi,%rcx,1),%rdi
  53709b:	48 83 c7 05          	add    $0x5,%rdi
  53709f:	0f b6 d0             	movzbl %al,%edx
  5370a2:	c1 e2 04             	shl    $0x4,%edx
  5370a5:	41 0f b7 4e 10       	movzwl 0x10(%r14),%ecx
  5370aa:	48 01 ca             	add    %rcx,%rdx
  5370ad:	45 0f b7 66 12       	movzwl 0x12(%r14),%r12d
  5370b2:	4c 01 e2             	add    %r12,%rdx
  5370b5:	48 83 c2 05          	add    $0x5,%rdx
  5370b9:	48 89 d6             	mov    %rdx,%rsi
  5370bc:	48 01 fe             	add    %rdi,%rsi
  5370bf:	0f 82 42 01 00 00    	jb     537207 <__cxa_finalize@plt-0x236039>
  5370c5:	4c 39 de             	cmp    %r11,%rsi
  5370c8:	0f 87 39 01 00 00    	ja     537207 <__cxa_finalize@plt-0x236039>
  5370ce:	48 01 df             	add    %rbx,%rdi
  5370d1:	a8 01                	test   $0x1,%al
  5370d3:	74 0f                	je     5370e4 <__cxa_finalize@plt-0x23615c>
  5370d5:	41 0f 10 45 00       	movups 0x0(%r13),%xmm0
  5370da:	0f 11 07             	movups %xmm0,(%rdi)
  5370dd:	b8 10 00 00 00       	mov    $0x10,%eax
  5370e2:	eb 02                	jmp    5370e6 <__cxa_finalize@plt-0x23615a>
  5370e4:	31 c0                	xor    %eax,%eax
  5370e6:	48 8d 70 05          	lea    0x5(%rax),%rsi
  5370ea:	48 39 d6             	cmp    %rdx,%rsi
  5370ed:	0f 87 31 01 00 00    	ja     537224 <__cxa_finalize@plt-0x23601c>
  5370f3:	45 0f b6 4e 14       	movzbl 0x14(%r14),%r9d
  5370f8:	44 88 0c 07          	mov    %r9b,(%rdi,%rax,1)
  5370fc:	41 89 c9             	mov    %ecx,%r9d
  5370ff:	66 41 c1 c1 08       	rol    $0x8,%r9w
  537104:	66 41 c1 c4 08       	rol    $0x8,%r12w
  537109:	66 44 89 4c 07 01    	mov    %r9w,0x1(%rdi,%rax,1)
  53710f:	66 44 89 64 07 03    	mov    %r12w,0x3(%rdi,%rax,1)
  537115:	48 01 ce             	add    %rcx,%rsi
  537118:	39 f2                	cmp    %esi,%edx
  53711a:	0f 82 d4 00 00 00    	jb     5371f4 <__cxa_finalize@plt-0x23604c>
  537120:	48 29 f2             	sub    %rsi,%rdx
  537123:	48 01 f7             	add    %rsi,%rdi
  537126:	31 f6                	xor    %esi,%esi
  537128:	4c 89 6c 24 10       	mov    %r13,0x10(%rsp)
  53712d:	4d 89 d5             	mov    %r10,%r13
  537130:	4c 89 44 24 18       	mov    %r8,0x18(%rsp)
  537135:	45 89 fc             	mov    %r15d,%r12d
  537138:	41 89 ef             	mov    %ebp,%r15d
  53713b:	4c 89 dd             	mov    %r11,%rbp
  53713e:	ff 15 d4 b7 27 00    	call   *0x27b7d4(%rip)        # 7b2918 <__stack_chk_fail@plt+0x456a8>
  537144:	49 89 eb             	mov    %rbp,%r11
  537147:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
  53714c:	4c 89 e9             	mov    %r13,%rcx
  53714f:	4c 8b 6c 24 10       	mov    0x10(%rsp),%r13
  537154:	8b 7c 24 0c          	mov    0xc(%rsp),%edi
  537158:	48 8b 54 24 20       	mov    0x20(%rsp),%rdx
  53715d:	40 0f b6 c7          	movzbl %dil,%eax
  537161:	c1 e0 04             	shl    $0x4,%eax
  537164:	48 01 ca             	add    %rcx,%rdx
  537167:	48 01 c2             	add    %rax,%rdx
  53716a:	48 83 c2 05          	add    $0x5,%rdx
  53716e:	48 89 d6             	mov    %rdx,%rsi
  537171:	4c 01 c6             	add    %r8,%rsi
  537174:	72 6b                	jb     5371e1 <__cxa_finalize@plt-0x23605f>
  537176:	4c 39 de             	cmp    %r11,%rsi
  537179:	77 66                	ja     5371e1 <__cxa_finalize@plt-0x23605f>
  53717b:	4c 01 c3             	add    %r8,%rbx
  53717e:	40 84 ff             	test   %dil,%dil
  537181:	74 0f                	je     537192 <__cxa_finalize@plt-0x2360ae>
  537183:	41 0f 10 45 00       	movups 0x0(%r13),%xmm0
  537188:	0f 11 03             	movups %xmm0,(%rbx)
  53718b:	bf 10 00 00 00       	mov    $0x10,%edi
  537190:	eb 02                	jmp    537194 <__cxa_finalize@plt-0x2360ac>
  537192:	31 ff                	xor    %edi,%edi
  537194:	48 8d 77 05          	lea    0x5(%rdi),%rsi
  537198:	48 39 d6             	cmp    %rdx,%rsi
  53719b:	77 7a                	ja     537217 <__cxa_finalize@plt-0x236029>
  53719d:	41 0f b6 46 1a       	movzbl 0x1a(%r14),%eax
  5371a2:	88 04 3b             	mov    %al,(%rbx,%rdi,1)
  5371a5:	66 41 c1 c7 08       	rol    $0x8,%r15w
  5371aa:	66 41 c1 c4 08       	rol    $0x8,%r12w
  5371af:	66 44 89 7c 3b 01    	mov    %r15w,0x1(%rbx,%rdi,1)
  5371b5:	66 44 89 64 3b 03    	mov    %r12w,0x3(%rbx,%rdi,1)
  5371bb:	48 01 ce             	add    %rcx,%rsi
  5371be:	39 f2                	cmp    %esi,%edx
  5371c0:	72 32                	jb     5371f4 <__cxa_finalize@plt-0x23604c>
  5371c2:	48 29 f2             	sub    %rsi,%rdx
  5371c5:	48 01 f3             	add    %rsi,%rbx
  5371c8:	48 89 df             	mov    %rbx,%rdi
  5371cb:	31 f6                	xor    %esi,%esi
  5371cd:	48 83 c4 28          	add    $0x28,%rsp
  5371d1:	5b                   	pop    %rbx
  5371d2:	41 5c                	pop    %r12
  5371d4:	41 5d                	pop    %r13
  5371d6:	41 5e                	pop    %r14
  5371d8:	41 5f                	pop    %r15
  5371da:	5d                   	pop    %rbp
  5371db:	ff 25 37 b7 27 00    	jmp    *0x27b737(%rip)        # 7b2918 <__stack_chk_fail@plt+0x456a8>
  5371e1:	48 8d 0d a8 b4 26 00 	lea    0x26b4a8(%rip),%rcx        # 7a2690 <__stack_chk_fail@plt+0x35420>
  5371e8:	4c 89 c7             	mov    %r8,%rdi
  5371eb:	4c 89 da             	mov    %r11,%rdx
  5371ee:	ff 15 84 b7 27 00    	call   *0x27b784(%rip)        # 7b2978 <__stack_chk_fail@plt+0x45708>
  5371f4:	48 8d 0d 25 b5 26 00 	lea    0x26b525(%rip),%rcx        # 7a2720 <__stack_chk_fail@plt+0x354b0>
  5371fb:	48 89 f7             	mov    %rsi,%rdi
  5371fe:	48 89 d6             	mov    %rdx,%rsi
  537201:	ff 15 71 b7 27 00    	call   *0x27b771(%rip)        # 7b2978 <__stack_chk_fail@plt+0x45708>
  537207:	48 8d 0d 6a b4 26 00 	lea    0x26b46a(%rip),%rcx        # 7a2678 <__stack_chk_fail@plt+0x35408>
  53720e:	4c 89 da             	mov    %r11,%rdx
  537211:	ff 15 61 b7 27 00    	call   *0x27b761(%rip)        # 7b2978 <__stack_chk_fail@plt+0x45708>
  537217:	48 8d 0d 1a b5 26 00 	lea    0x26b51a(%rip),%rcx        # 7a2738 <__stack_chk_fail@plt+0x354c8>
  53721e:	ff 15 54 b7 27 00    	call   *0x27b754(%rip)        # 7b2978 <__stack_chk_fail@plt+0x45708>
  537224:	48 8d 0d 0d b5 26 00 	lea    0x26b50d(%rip),%rcx        # 7a2738 <__stack_chk_fail@plt+0x354c8>
  53722b:	48 89 c7             	mov    %rax,%rdi
  53722e:	ff 15 44 b7 27 00    	call   *0x27b744(%rip)        # 7b2978 <__stack_chk_fail@plt+0x45708>
  537234:	cc                   	int3
  537235:	cc                   	int3
  537236:	cc                   	int3
  537237:	cc                   	int3
  537238:	cc                   	int3
  537239:	cc                   	int3
  53723a:	cc                   	int3
  53723b:	cc                   	int3
  53723c:	cc                   	int3
  53723d:	cc                   	int3
  53723e:	cc                   	int3
  53723f:	cc                   	int3
