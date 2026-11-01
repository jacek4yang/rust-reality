
/home/jacek/.cache/rr-v230-vectored-75a1-gnu/rust-reality:     file format elf64-x86-64


Disassembly of section .text:

0000000000536eb0 <.text+0x357630>:
  536eb0:	55                   	push   %rbp
  536eb1:	41 57                	push   %r15
  536eb3:	41 56                	push   %r14
  536eb5:	41 55                	push   %r13
  536eb7:	41 54                	push   %r12
  536eb9:	53                   	push   %rbx
  536eba:	48 83 ec 28          	sub    $0x28,%rsp
  536ebe:	49 89 cb             	mov    %rcx,%r11
  536ec1:	48 89 d3             	mov    %rdx,%rbx
  536ec4:	49 89 f5             	mov    %rsi,%r13
  536ec7:	49 89 fe             	mov    %rdi,%r14
  536eca:	0f b6 47 15          	movzbl 0x15(%rdi),%eax
  536ece:	3c 02                	cmp    $0x2,%al
  536ed0:	75 1c                	jne    536eee <__cxa_finalize@plt-0x238752>
  536ed2:	41 0f b6 7e 1b       	movzbl 0x1b(%r14),%edi
  536ed7:	45 0f b7 7e 16       	movzwl 0x16(%r14),%r15d
  536edc:	45 0f b7 66 18       	movzwl 0x18(%r14),%r12d
  536ee1:	41 0f b7 cf          	movzwl %r15w,%ecx
  536ee5:	41 0f b7 d4          	movzwl %r12w,%edx
  536ee9:	e9 ef 00 00 00       	jmp    536fdd <__cxa_finalize@plt-0x238663>
  536eee:	41 0f b6 4e 1b       	movzbl 0x1b(%r14),%ecx
  536ef3:	89 4c 24 0c          	mov    %ecx,0xc(%rsp)
  536ef7:	c1 e1 04             	shl    $0x4,%ecx
  536efa:	41 0f b7 6e 16       	movzwl 0x16(%r14),%ebp
  536eff:	45 0f b7 7e 18       	movzwl 0x18(%r14),%r15d
  536f04:	44 0f b7 d5          	movzwl %bp,%r10d
  536f08:	41 0f b7 f7          	movzwl %r15w,%esi
  536f0c:	4c 01 c1             	add    %r8,%rcx
  536f0f:	4c 01 d1             	add    %r10,%rcx
  536f12:	48 89 74 24 20       	mov    %rsi,0x20(%rsp)
  536f17:	48 8d 3c 0e          	lea    (%rsi,%rcx,1),%rdi
  536f1b:	48 83 c7 05          	add    $0x5,%rdi
  536f1f:	0f b6 d0             	movzbl %al,%edx
  536f22:	c1 e2 04             	shl    $0x4,%edx
  536f25:	41 0f b7 4e 10       	movzwl 0x10(%r14),%ecx
  536f2a:	48 01 ca             	add    %rcx,%rdx
  536f2d:	45 0f b7 66 12       	movzwl 0x12(%r14),%r12d
  536f32:	4c 01 e2             	add    %r12,%rdx
  536f35:	48 83 c2 05          	add    $0x5,%rdx
  536f39:	48 89 d6             	mov    %rdx,%rsi
  536f3c:	48 01 fe             	add    %rdi,%rsi
  536f3f:	0f 82 42 01 00 00    	jb     537087 <__cxa_finalize@plt-0x2385b9>
  536f45:	4c 39 de             	cmp    %r11,%rsi
  536f48:	0f 87 39 01 00 00    	ja     537087 <__cxa_finalize@plt-0x2385b9>
  536f4e:	48 01 df             	add    %rbx,%rdi
  536f51:	a8 01                	test   $0x1,%al
  536f53:	74 0f                	je     536f64 <__cxa_finalize@plt-0x2386dc>
  536f55:	41 0f 10 45 00       	movups 0x0(%r13),%xmm0
  536f5a:	0f 11 07             	movups %xmm0,(%rdi)
  536f5d:	b8 10 00 00 00       	mov    $0x10,%eax
  536f62:	eb 02                	jmp    536f66 <__cxa_finalize@plt-0x2386da>
  536f64:	31 c0                	xor    %eax,%eax
  536f66:	48 8d 70 05          	lea    0x5(%rax),%rsi
  536f6a:	48 39 d6             	cmp    %rdx,%rsi
  536f6d:	0f 87 31 01 00 00    	ja     5370a4 <__cxa_finalize@plt-0x23859c>
  536f73:	45 0f b6 4e 14       	movzbl 0x14(%r14),%r9d
  536f78:	44 88 0c 07          	mov    %r9b,(%rdi,%rax,1)
  536f7c:	41 89 c9             	mov    %ecx,%r9d
  536f7f:	66 41 c1 c1 08       	rol    $0x8,%r9w
  536f84:	66 41 c1 c4 08       	rol    $0x8,%r12w
  536f89:	66 44 89 4c 07 01    	mov    %r9w,0x1(%rdi,%rax,1)
  536f8f:	66 44 89 64 07 03    	mov    %r12w,0x3(%rdi,%rax,1)
  536f95:	48 01 ce             	add    %rcx,%rsi
  536f98:	39 f2                	cmp    %esi,%edx
  536f9a:	0f 82 d4 00 00 00    	jb     537074 <__cxa_finalize@plt-0x2385cc>
  536fa0:	48 29 f2             	sub    %rsi,%rdx
  536fa3:	48 01 f7             	add    %rsi,%rdi
  536fa6:	31 f6                	xor    %esi,%esi
  536fa8:	4c 89 6c 24 10       	mov    %r13,0x10(%rsp)
  536fad:	4d 89 d5             	mov    %r10,%r13
  536fb0:	4c 89 44 24 18       	mov    %r8,0x18(%rsp)
  536fb5:	45 89 fc             	mov    %r15d,%r12d
  536fb8:	41 89 ef             	mov    %ebp,%r15d
  536fbb:	4c 89 dd             	mov    %r11,%rbp
  536fbe:	ff 15 54 dd 27 00    	call   *0x27dd54(%rip)        # 7b4d18 <__stack_chk_fail@plt+0x456a8>
  536fc4:	49 89 eb             	mov    %rbp,%r11
  536fc7:	4c 8b 44 24 18       	mov    0x18(%rsp),%r8
  536fcc:	4c 89 e9             	mov    %r13,%rcx
  536fcf:	4c 8b 6c 24 10       	mov    0x10(%rsp),%r13
  536fd4:	8b 7c 24 0c          	mov    0xc(%rsp),%edi
  536fd8:	48 8b 54 24 20       	mov    0x20(%rsp),%rdx
  536fdd:	40 0f b6 c7          	movzbl %dil,%eax
  536fe1:	c1 e0 04             	shl    $0x4,%eax
  536fe4:	48 01 ca             	add    %rcx,%rdx
  536fe7:	48 01 c2             	add    %rax,%rdx
  536fea:	48 83 c2 05          	add    $0x5,%rdx
  536fee:	48 89 d6             	mov    %rdx,%rsi
  536ff1:	4c 01 c6             	add    %r8,%rsi
  536ff4:	72 6b                	jb     537061 <__cxa_finalize@plt-0x2385df>
  536ff6:	4c 39 de             	cmp    %r11,%rsi
  536ff9:	77 66                	ja     537061 <__cxa_finalize@plt-0x2385df>
  536ffb:	4c 01 c3             	add    %r8,%rbx
  536ffe:	40 84 ff             	test   %dil,%dil
  537001:	74 0f                	je     537012 <__cxa_finalize@plt-0x23862e>
  537003:	41 0f 10 45 00       	movups 0x0(%r13),%xmm0
  537008:	0f 11 03             	movups %xmm0,(%rbx)
  53700b:	bf 10 00 00 00       	mov    $0x10,%edi
  537010:	eb 02                	jmp    537014 <__cxa_finalize@plt-0x23862c>
  537012:	31 ff                	xor    %edi,%edi
  537014:	48 8d 77 05          	lea    0x5(%rdi),%rsi
  537018:	48 39 d6             	cmp    %rdx,%rsi
  53701b:	77 7a                	ja     537097 <__cxa_finalize@plt-0x2385a9>
  53701d:	41 0f b6 46 1a       	movzbl 0x1a(%r14),%eax
  537022:	88 04 3b             	mov    %al,(%rbx,%rdi,1)
  537025:	66 41 c1 c7 08       	rol    $0x8,%r15w
  53702a:	66 41 c1 c4 08       	rol    $0x8,%r12w
  53702f:	66 44 89 7c 3b 01    	mov    %r15w,0x1(%rbx,%rdi,1)
  537035:	66 44 89 64 3b 03    	mov    %r12w,0x3(%rbx,%rdi,1)
  53703b:	48 01 ce             	add    %rcx,%rsi
  53703e:	39 f2                	cmp    %esi,%edx
  537040:	72 32                	jb     537074 <__cxa_finalize@plt-0x2385cc>
  537042:	48 29 f2             	sub    %rsi,%rdx
  537045:	48 01 f3             	add    %rsi,%rbx
  537048:	48 89 df             	mov    %rbx,%rdi
  53704b:	31 f6                	xor    %esi,%esi
  53704d:	48 83 c4 28          	add    $0x28,%rsp
  537051:	5b                   	pop    %rbx
  537052:	41 5c                	pop    %r12
  537054:	41 5d                	pop    %r13
  537056:	41 5e                	pop    %r14
  537058:	41 5f                	pop    %r15
  53705a:	5d                   	pop    %rbp
  53705b:	ff 25 b7 dc 27 00    	jmp    *0x27dcb7(%rip)        # 7b4d18 <__stack_chk_fail@plt+0x456a8>
  537061:	48 8d 0d 28 da 26 00 	lea    0x26da28(%rip),%rcx        # 7a4a90 <__stack_chk_fail@plt+0x35420>
  537068:	4c 89 c7             	mov    %r8,%rdi
  53706b:	4c 89 da             	mov    %r11,%rdx
  53706e:	ff 15 04 dd 27 00    	call   *0x27dd04(%rip)        # 7b4d78 <__stack_chk_fail@plt+0x45708>
  537074:	48 8d 0d a5 da 26 00 	lea    0x26daa5(%rip),%rcx        # 7a4b20 <__stack_chk_fail@plt+0x354b0>
  53707b:	48 89 f7             	mov    %rsi,%rdi
  53707e:	48 89 d6             	mov    %rdx,%rsi
  537081:	ff 15 f1 dc 27 00    	call   *0x27dcf1(%rip)        # 7b4d78 <__stack_chk_fail@plt+0x45708>
  537087:	48 8d 0d ea d9 26 00 	lea    0x26d9ea(%rip),%rcx        # 7a4a78 <__stack_chk_fail@plt+0x35408>
  53708e:	4c 89 da             	mov    %r11,%rdx
  537091:	ff 15 e1 dc 27 00    	call   *0x27dce1(%rip)        # 7b4d78 <__stack_chk_fail@plt+0x45708>
  537097:	48 8d 0d 9a da 26 00 	lea    0x26da9a(%rip),%rcx        # 7a4b38 <__stack_chk_fail@plt+0x354c8>
  53709e:	ff 15 d4 dc 27 00    	call   *0x27dcd4(%rip)        # 7b4d78 <__stack_chk_fail@plt+0x45708>
  5370a4:	48 8d 0d 8d da 26 00 	lea    0x26da8d(%rip),%rcx        # 7a4b38 <__stack_chk_fail@plt+0x354c8>
  5370ab:	48 89 c7             	mov    %rax,%rdi
  5370ae:	ff 15 c4 dc 27 00    	call   *0x27dcc4(%rip)        # 7b4d78 <__stack_chk_fail@plt+0x45708>
  5370b4:	cc                   	int3
  5370b5:	cc                   	int3
  5370b6:	cc                   	int3
  5370b7:	cc                   	int3
  5370b8:	cc                   	int3
  5370b9:	cc                   	int3
  5370ba:	cc                   	int3
  5370bb:	cc                   	int3
  5370bc:	cc                   	int3
  5370bd:	cc                   	int3
  5370be:	cc                   	int3
  5370bf:	cc                   	int3
