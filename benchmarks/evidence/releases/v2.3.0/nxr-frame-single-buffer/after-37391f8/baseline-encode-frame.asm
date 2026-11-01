
/home/jacek/.cache/rr-v230-nxr-frame-profile/probe:     file format elf64-x86-64


Disassembly of section .text:

0000000000055b00 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame>:
   55b00:	55                   	push   %rbp
   55b01:	41 57                	push   %r15
   55b03:	41 56                	push   %r14
   55b05:	41 55                	push   %r13
   55b07:	41 54                	push   %r12
   55b09:	53                   	push   %rbx
   55b0a:	48 83 ec 78          	sub    $0x78,%rsp
   55b0e:	48 8b 9c 24 b0 00 00 	mov    0xb0(%rsp),%rbx
   55b15:	00
   55b16:	b0 0a                	mov    $0xa,%al
   55b18:	48 81 fb 66 1d 00 00 	cmp    $0x1d66,%rbx
   55b1f:	0f 87 e8 03 00 00    	ja     55f0d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x40d>
   55b25:	44 8d 52 ff          	lea    -0x1(%rdx),%r10d
   55b29:	b0 0b                	mov    $0xb,%al
   55b2b:	41 80 fa 01          	cmp    $0x1,%r10b
   55b2f:	0f 87 d8 03 00 00    	ja     55f0d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x40d>
   55b35:	b0 0c                	mov    $0xc,%al
   55b37:	40 80 fe 01          	cmp    $0x1,%sil
   55b3b:	0f 87 cc 03 00 00    	ja     55f0d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x40d>
   55b41:	4d 85 c0             	test   %r8,%r8
   55b44:	74 49                	je     55b8f <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x8f>
   55b46:	49 8b 00             	mov    (%r8),%rax
   55b49:	4d 8b 58 10          	mov    0x10(%r8),%r11
   55b4d:	49 ba 00 00 00 00 00 	movabs $0x8000000000000000,%r10
   55b54:	00 00 80
   55b57:	49 31 c2             	xor    %rax,%r10
   55b5a:	48 85 c0             	test   %rax,%rax
   55b5d:	41 bc 01 00 00 00    	mov    $0x1,%r12d
   55b63:	4d 0f 48 e2          	cmovs  %r10,%r12
   55b67:	4d 85 e4             	test   %r12,%r12
   55b6a:	74 37                	je     55ba3 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xa3>
   55b6c:	49 83 fc 01          	cmp    $0x1,%r12
   55b70:	75 3c                	jne    55bae <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xae>
   55b72:	4d 8d 93 02 ff ff ff 	lea    -0xfe(%r11),%r10
   55b79:	40 b5 02             	mov    $0x2,%bpl
   55b7c:	b0 05                	mov    $0x5,%al
   55b7e:	4d 89 df             	mov    %r11,%r15
   55b81:	49 81 fa 03 ff ff ff 	cmp    $0xffffffffffffff03,%r10
   55b88:	73 2d                	jae    55bb7 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xb7>
   55b8a:	e9 7e 03 00 00       	jmp    55f0d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x40d>
   55b8f:	bd 08 00 00 00       	mov    $0x8,%ebp
   55b94:	49 c7 c7 ff ff ff ff 	mov    $0xffffffffffffffff,%r15
   55b9b:	45 31 ed             	xor    %r13d,%r13d
   55b9e:	e9 92 01 00 00       	jmp    55d35 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x235>
   55ba3:	41 bf 04 00 00 00    	mov    $0x4,%r15d
   55ba9:	40 b5 01             	mov    $0x1,%bpl
   55bac:	eb 09                	jmp    55bb7 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0xb7>
   55bae:	41 bf 10 00 00 00    	mov    $0x10,%r15d
   55bb4:	40 b5 03             	mov    $0x3,%bpl
   55bb7:	4c 89 5c 24 70       	mov    %r11,0x70(%rsp)
   55bbc:	45 0f b7 68 18       	movzwl 0x18(%r8),%r13d
   55bc1:	66 45 85 ed          	test   %r13w,%r13w
   55bc5:	0f 84 f1 00 00 00    	je     55cbc <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x1bc>
   55bcb:	4c 89 44 24 60       	mov    %r8,0x60(%rsp)
   55bd0:	48 89 54 24 10       	mov    %rdx,0x10(%rsp)
   55bd5:	89 4c 24 0c          	mov    %ecx,0xc(%rsp)
   55bd9:	4c 89 4c 24 30       	mov    %r9,0x30(%rsp)
   55bde:	89 74 24 08          	mov    %esi,0x8(%rsp)
   55be2:	48 89 7c 24 38       	mov    %rdi,0x38(%rsp)
   55be7:	4d 8d 77 05          	lea    0x5(%r15),%r14
   55beb:	67 e8 2c 19 fc ff    	addr32 call 1751d <_RNvCs5fGHjzWXRav_7___rustc35___rust_no_alloc_shim_is_unstable_v2>
   55bf1:	be 01 00 00 00       	mov    $0x1,%esi
   55bf6:	4c 89 f7             	mov    %r14,%rdi
   55bf9:	67 e8 01 19 fc ff    	addr32 call 17500 <_RNvCs5fGHjzWXRav_7___rustc12___rust_alloc>
   55bff:	48 85 c0             	test   %rax,%rax
   55c02:	0f 84 2e 04 00 00    	je     56036 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x536>
   55c08:	4c 89 74 24 40       	mov    %r14,0x40(%rsp)
   55c0d:	48 89 44 24 48       	mov    %rax,0x48(%rsp)
   55c12:	40 88 28             	mov    %bpl,(%rax)
   55c15:	44 89 f9             	mov    %r15d,%ecx
   55c18:	66 c1 c1 08          	rol    $0x8,%cx
   55c1c:	66 89 48 01          	mov    %cx,0x1(%rax)
   55c20:	66 41 c1 c5 08       	rol    $0x8,%r13w
   55c25:	66 44 89 68 03       	mov    %r13w,0x3(%rax)
   55c2a:	48 c7 44 24 50 05 00 	movq   $0x5,0x50(%rsp)
   55c31:	00 00
   55c33:	49 89 c6             	mov    %rax,%r14
   55c36:	49 c1 ee 08          	shr    $0x8,%r14
   55c3a:	4c 8b 44 24 60       	mov    0x60(%rsp),%r8
   55c3f:	49 83 c0 08          	add    $0x8,%r8
   55c43:	4d 85 e4             	test   %r12,%r12
   55c46:	74 7b                	je     55cc3 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x1c3>
   55c48:	49 83 fc 01          	cmp    $0x1,%r12
   55c4c:	48 8b 7c 24 38       	mov    0x38(%rsp),%rdi
   55c51:	8b 74 24 08          	mov    0x8(%rsp),%esi
   55c55:	4c 8b 4c 24 30       	mov    0x30(%rsp),%r9
   55c5a:	8b 4c 24 0c          	mov    0xc(%rsp),%ecx
   55c5e:	48 8b 54 24 10       	mov    0x10(%rsp),%rdx
   55c63:	0f 85 8e 00 00 00    	jne    55cf7 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x1f7>
   55c69:	49 8b 30             	mov    (%r8),%rsi
   55c6c:	4c 8b 6c 24 70       	mov    0x70(%rsp),%r13
   55c71:	4d 39 fd             	cmp    %r15,%r13
   55c74:	0f 87 03 03 00 00    	ja     55f7d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x47d>
   55c7a:	41 bc 05 00 00 00    	mov    $0x5,%r12d
   55c80:	48 89 c7             	mov    %rax,%rdi
   55c83:	4d 85 ed             	test   %r13,%r13
   55c86:	74 18                	je     55ca0 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x1a0>
   55c88:	4c 01 e7             	add    %r12,%rdi
   55c8b:	4c 89 ea             	mov    %r13,%rdx
   55c8e:	4d 89 f7             	mov    %r14,%r15
   55c91:	49 89 c6             	mov    %rax,%r14
   55c94:	ff 15 be 67 00 00    	call   *0x67be(%rip)        # 5c458 <memcpy@GLIBC_2.14>
   55c9a:	4c 89 f0             	mov    %r14,%rax
   55c9d:	4d 89 fe             	mov    %r15,%r14
   55ca0:	4d 01 ec             	add    %r13,%r12
   55ca3:	48 8b 7c 24 38       	mov    0x38(%rsp),%rdi
   55ca8:	8b 74 24 08          	mov    0x8(%rsp),%esi
   55cac:	4c 8b 4c 24 30       	mov    0x30(%rsp),%r9
   55cb1:	8b 4c 24 0c          	mov    0xc(%rsp),%ecx
   55cb5:	48 8b 54 24 10       	mov    0x10(%rsp),%rdx
   55cba:	eb 58                	jmp    55d14 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x214>
   55cbc:	b0 06                	mov    $0x6,%al
   55cbe:	e9 4a 02 00 00       	jmp    55f0d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x40d>
   55cc3:	41 8b 28             	mov    (%r8),%ebp
   55cc6:	41 bc 05 00 00 00    	mov    $0x5,%r12d
   55ccc:	49 83 ff 03          	cmp    $0x3,%r15
   55cd0:	48 8b 7c 24 38       	mov    0x38(%rsp),%rdi
   55cd5:	8b 74 24 08          	mov    0x8(%rsp),%esi
   55cd9:	4c 8b 4c 24 30       	mov    0x30(%rsp),%r9
   55cde:	8b 4c 24 0c          	mov    0xc(%rsp),%ecx
   55ce2:	48 8b 54 24 10       	mov    0x10(%rsp),%rdx
   55ce7:	0f 86 c1 02 00 00    	jbe    55fae <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x4ae>
   55ced:	42 89 2c 20          	mov    %ebp,(%rax,%r12,1)
   55cf1:	49 83 c4 04          	add    $0x4,%r12
   55cf5:	eb 1d                	jmp    55d14 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x214>
   55cf7:	41 bc 05 00 00 00    	mov    $0x5,%r12d
   55cfd:	49 83 ff 0f          	cmp    $0xf,%r15
   55d01:	0f 86 e8 02 00 00    	jbe    55fef <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x4ef>
   55d07:	41 0f 10 00          	movups (%r8),%xmm0
   55d0b:	42 0f 11 04 20       	movups %xmm0,(%rax,%r12,1)
   55d10:	49 83 c4 10          	add    $0x10,%r12
   55d14:	4c 8b 7c 24 40       	mov    0x40(%rsp),%r15
   55d19:	49 83 ff ff          	cmp    $0xffffffffffffffff,%r15
   55d1d:	0f 84 ea 01 00 00    	je     55f0d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x40d>
   55d23:	0f b6 c0             	movzbl %al,%eax
   55d26:	49 c1 e6 08          	shl    $0x8,%r14
   55d2a:	49 09 c6             	or     %rax,%r14
   55d2d:	49 8d 6c 24 08       	lea    0x8(%r12),%rbp
   55d32:	41 b5 01             	mov    $0x1,%r13b
   55d35:	48 01 dd             	add    %rbx,%rbp
   55d38:	48 81 fd 70 1e 00 00 	cmp    $0x1e70,%rbp
   55d3f:	76 07                	jbe    55d48 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x248>
   55d41:	31 c0                	xor    %eax,%eax
   55d43:	e9 a4 01 00 00       	jmp    55eec <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x3ec>
   55d48:	4c 89 74 24 10       	mov    %r14,0x10(%rsp)
   55d4d:	49 89 d6             	mov    %rdx,%r14
   55d50:	89 4c 24 0c          	mov    %ecx,0xc(%rsp)
   55d54:	4c 89 4c 24 30       	mov    %r9,0x30(%rsp)
   55d59:	89 74 24 08          	mov    %esi,0x8(%rsp)
   55d5d:	48 89 7c 24 38       	mov    %rdi,0x38(%rsp)
   55d62:	48 c7 44 24 18 00 00 	movq   $0x0,0x18(%rsp)
   55d69:	00 00
   55d6b:	48 c7 44 24 20 01 00 	movq   $0x1,0x20(%rsp)
   55d72:	00 00
   55d74:	48 c7 44 24 28 00 00 	movq   $0x0,0x28(%rsp)
   55d7b:	00 00
   55d7d:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
   55d82:	ba 01 00 00 00       	mov    $0x1,%edx
   55d87:	31 f6                	xor    %esi,%esi
   55d89:	48 89 e9             	mov    %rbp,%rcx
   55d8c:	e8 8f f1 ff ff       	call   54f20 <_RNvMs5_NtCsgFX3jaOk65H_5alloc7raw_vecNtB5_11RawVecInner11finish_growCsHnFHAC5PMO_12rust_reality>
   55d91:	83 7c 24 40 01       	cmpl   $0x1,0x40(%rsp)
   55d96:	75 0c                	jne    55da4 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x2a4>
   55d98:	b0 09                	mov    $0x9,%al
   55d9a:	4c 8b 74 24 10       	mov    0x10(%rsp),%r14
   55d9f:	e9 28 01 00 00       	jmp    55ecc <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x3cc>
   55da4:	4c 89 64 24 60       	mov    %r12,0x60(%rsp)
   55da9:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
   55dae:	48 89 44 24 20       	mov    %rax,0x20(%rsp)
   55db3:	48 89 6c 24 18       	mov    %rbp,0x18(%rsp)
   55db8:	4c 8b 64 24 28       	mov    0x28(%rsp),%r12
   55dbd:	49 39 ec             	cmp    %rbp,%r12
   55dc0:	75 10                	jne    55dd2 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x2d2>
   55dc2:	48 8d 7c 24 18       	lea    0x18(%rsp),%rdi
   55dc7:	67 e8 a3 71 ff ff    	addr32 call 4cf70 <_RNvMs4_NtCsgFX3jaOk65H_5alloc7raw_vecINtB5_6RawVechE8grow_oneB7_>
   55dcd:	48 8b 44 24 20       	mov    0x20(%rsp),%rax
   55dd2:	46 88 34 20          	mov    %r14b,(%rax,%r12,1)
   55dd6:	49 8d 44 24 01       	lea    0x1(%r12),%rax
   55ddb:	48 89 44 24 28       	mov    %rax,0x28(%rsp)
   55de0:	48 3b 44 24 18       	cmp    0x18(%rsp),%rax
   55de5:	75 0b                	jne    55df2 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x2f2>
   55de7:	48 8d 7c 24 18       	lea    0x18(%rsp),%rdi
   55dec:	67 e8 7e 71 ff ff    	addr32 call 4cf70 <_RNvMs4_NtCsgFX3jaOk65H_5alloc7raw_vecINtB5_6RawVechE8grow_oneB7_>
   55df2:	48 8b ac 24 b8 00 00 	mov    0xb8(%rsp),%rbp
   55df9:	00
   55dfa:	48 8b 44 24 20       	mov    0x20(%rsp),%rax
   55dff:	46 88 6c 20 01       	mov    %r13b,0x1(%rax,%r12,1)
   55e04:	49 83 c4 02          	add    $0x2,%r12
   55e08:	4c 89 64 24 28       	mov    %r12,0x28(%rsp)
   55e0d:	8b 44 24 0c          	mov    0xc(%rsp),%eax
   55e11:	0f c8                	bswap  %eax
   55e13:	89 44 24 40          	mov    %eax,0x40(%rsp)
   55e17:	48 8d 7c 24 18       	lea    0x18(%rsp),%rdi
   55e1c:	48 8d 74 24 40       	lea    0x40(%rsp),%rsi
   55e21:	ba 04 00 00 00       	mov    $0x4,%edx
   55e26:	e8 75 f1 ff ff       	call   54fa0 <_RNvMs_NtCsgFX3jaOk65H_5alloc3vecINtB4_3VechE15append_elementsCsHnFHAC5PMO_12rust_reality>
   55e2b:	49 83 ff ff          	cmp    $0xffffffffffffffff,%r15
   55e2f:	4c 8b 74 24 10       	mov    0x10(%rsp),%r14
   55e34:	74 12                	je     55e48 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x348>
   55e36:	48 8d 7c 24 18       	lea    0x18(%rsp),%rdi
   55e3b:	4c 89 f6             	mov    %r14,%rsi
   55e3e:	48 8b 54 24 60       	mov    0x60(%rsp),%rdx
   55e43:	e8 58 f1 ff ff       	call   54fa0 <_RNvMs_NtCsgFX3jaOk65H_5alloc3vecINtB4_3VechE15append_elementsCsHnFHAC5PMO_12rust_reality>
   55e48:	89 d8                	mov    %ebx,%eax
   55e4a:	66 c1 c0 08          	rol    $0x8,%ax
   55e4e:	66 89 44 24 40       	mov    %ax,0x40(%rsp)
   55e53:	4c 8d 64 24 18       	lea    0x18(%rsp),%r12
   55e58:	48 8d 74 24 40       	lea    0x40(%rsp),%rsi
   55e5d:	ba 02 00 00 00       	mov    $0x2,%edx
   55e62:	4c 89 e7             	mov    %r12,%rdi
   55e65:	e8 36 f1 ff ff       	call   54fa0 <_RNvMs_NtCsgFX3jaOk65H_5alloc3vecINtB4_3VechE15append_elementsCsHnFHAC5PMO_12rust_reality>
   55e6a:	4c 89 e7             	mov    %r12,%rdi
   55e6d:	48 8b 74 24 30       	mov    0x30(%rsp),%rsi
   55e72:	48 89 da             	mov    %rbx,%rdx
   55e75:	e8 26 f1 ff ff       	call   54fa0 <_RNvMs_NtCsgFX3jaOk65H_5alloc3vecINtB4_3VechE15append_elementsCsHnFHAC5PMO_12rust_reality>
   55e7a:	48 8b 4c 24 20       	mov    0x20(%rsp),%rcx
   55e7f:	4c 8b 44 24 28       	mov    0x28(%rsp),%r8
   55e84:	0f b6 54 24 08       	movzbl 0x8(%rsp),%edx
   55e89:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
   55e8e:	48 8b 74 24 38       	mov    0x38(%rsp),%rsi
   55e93:	e8 28 e9 ff ff       	call   547c0 <_RNvMs1_NtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4keysNtB5_16NxrUdpSessionKey9frame_tag>
   55e98:	48 8b 74 24 28       	mov    0x28(%rsp),%rsi
   55e9d:	48 83 c6 24          	add    $0x24,%rsi
   55ea1:	48 c7 45 10 00 00 00 	movq   $0x0,0x10(%rbp)
   55ea8:	00
   55ea9:	48 89 ef             	mov    %rbp,%rdi
   55eac:	e8 0f f0 ff ff       	call   54ec0 <_RNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecNtB5_11RawVecInner17try_reserve_exactCsHnFHAC5PMO_12rust_reality>
   55eb1:	48 89 c1             	mov    %rax,%rcx
   55eb4:	b0 09                	mov    $0x9,%al
   55eb6:	48 83 f9 ff          	cmp    $0xffffffffffffffff,%rcx
   55eba:	75 10                	jne    55ecc <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x3cc>
   55ebc:	48 8b 44 24 28       	mov    0x28(%rsp),%rax
   55ec1:	48 89 c1             	mov    %rax,%rcx
   55ec4:	48 c1 e9 20          	shr    $0x20,%rcx
   55ec8:	74 52                	je     55f1c <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x41c>
   55eca:	31 c0                	xor    %eax,%eax
   55ecc:	48 8b 74 24 18       	mov    0x18(%rsp),%rsi
   55ed1:	48 85 f6             	test   %rsi,%rsi
   55ed4:	74 16                	je     55eec <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x3ec>
   55ed6:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
   55edb:	ba 01 00 00 00       	mov    $0x1,%edx
   55ee0:	48 89 c3             	mov    %rax,%rbx
   55ee3:	67 e8 1f 16 fc ff    	addr32 call 17508 <_RNvCs5fGHjzWXRav_7___rustc14___rust_dealloc>
   55ee9:	48 89 d8             	mov    %rbx,%rax
   55eec:	49 8d 4f ff          	lea    -0x1(%r15),%rcx
   55ef0:	48 83 f9 fe          	cmp    $0xfffffffffffffffe,%rcx
   55ef4:	73 17                	jae    55f0d <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x40d>
   55ef6:	ba 01 00 00 00       	mov    $0x1,%edx
   55efb:	4c 89 f7             	mov    %r14,%rdi
   55efe:	4c 89 fe             	mov    %r15,%rsi
   55f01:	48 89 c3             	mov    %rax,%rbx
   55f04:	67 e8 fe 15 fc ff    	addr32 call 17508 <_RNvCs5fGHjzWXRav_7___rustc14___rust_dealloc>
   55f0a:	48 89 d8             	mov    %rbx,%rax
   55f0d:	48 83 c4 78          	add    $0x78,%rsp
   55f11:	5b                   	pop    %rbx
   55f12:	41 5c                	pop    %r12
   55f14:	41 5d                	pop    %r13
   55f16:	41 5e                	pop    %r14
   55f18:	41 5f                	pop    %r15
   55f1a:	5d                   	pop    %rbp
   55f1b:	c3                   	ret
   55f1c:	0f c8                	bswap  %eax
   55f1e:	89 44 24 6c          	mov    %eax,0x6c(%rsp)
   55f22:	48 8d 74 24 6c       	lea    0x6c(%rsp),%rsi
   55f27:	ba 04 00 00 00       	mov    $0x4,%edx
   55f2c:	48 89 ef             	mov    %rbp,%rdi
   55f2f:	e8 6c f0 ff ff       	call   54fa0 <_RNvMs_NtCsgFX3jaOk65H_5alloc3vecINtB4_3VechE15append_elementsCsHnFHAC5PMO_12rust_reality>
   55f34:	48 8b 74 24 20       	mov    0x20(%rsp),%rsi
   55f39:	48 8b 54 24 28       	mov    0x28(%rsp),%rdx
   55f3e:	48 89 ef             	mov    %rbp,%rdi
   55f41:	e8 5a f0 ff ff       	call   54fa0 <_RNvMs_NtCsgFX3jaOk65H_5alloc3vecINtB4_3VechE15append_elementsCsHnFHAC5PMO_12rust_reality>
   55f46:	48 8d 74 24 40       	lea    0x40(%rsp),%rsi
   55f4b:	ba 20 00 00 00       	mov    $0x20,%edx
   55f50:	48 89 ef             	mov    %rbp,%rdi
   55f53:	e8 48 f0 ff ff       	call   54fa0 <_RNvMs_NtCsgFX3jaOk65H_5alloc3vecINtB4_3VechE15append_elementsCsHnFHAC5PMO_12rust_reality>
   55f58:	48 8b 74 24 18       	mov    0x18(%rsp),%rsi
   55f5d:	48 85 f6             	test   %rsi,%rsi
   55f60:	74 10                	je     55f72 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x472>
   55f62:	48 8b 7c 24 20       	mov    0x20(%rsp),%rdi
   55f67:	ba 01 00 00 00       	mov    $0x1,%edx
   55f6c:	67 e8 96 15 fc ff    	addr32 call 17508 <_RNvCs5fGHjzWXRav_7___rustc14___rust_dealloc>
   55f72:	49 8d 4f ff          	lea    -0x1(%r15),%rcx
   55f76:	b0 ff                	mov    $0xff,%al
   55f78:	e9 73 ff ff ff       	jmp    55ef0 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x3f0>
   55f7d:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
   55f82:	49 89 f6             	mov    %rsi,%r14
   55f85:	be 05 00 00 00       	mov    $0x5,%esi
   55f8a:	4c 89 ea             	mov    %r13,%rdx
   55f8d:	e8 0e de ff ff       	call   53da0 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55f92:	4c 89 f6             	mov    %r14,%rsi
   55f95:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
   55f9a:	4c 8b 64 24 50       	mov    0x50(%rsp),%r12
   55f9f:	49 89 c6             	mov    %rax,%r14
   55fa2:	49 c1 ee 08          	shr    $0x8,%r14
   55fa6:	48 89 c7             	mov    %rax,%rdi
   55fa9:	e9 da fc ff ff       	jmp    55c88 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x188>
   55fae:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
   55fb3:	be 05 00 00 00       	mov    $0x5,%esi
   55fb8:	ba 04 00 00 00       	mov    $0x4,%edx
   55fbd:	e8 de dd ff ff       	call   53da0 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   55fc2:	48 8b 54 24 10       	mov    0x10(%rsp),%rdx
   55fc7:	8b 4c 24 0c          	mov    0xc(%rsp),%ecx
   55fcb:	4c 8b 4c 24 30       	mov    0x30(%rsp),%r9
   55fd0:	8b 74 24 08          	mov    0x8(%rsp),%esi
   55fd4:	48 8b 7c 24 38       	mov    0x38(%rsp),%rdi
   55fd9:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
   55fde:	4c 8b 64 24 50       	mov    0x50(%rsp),%r12
   55fe3:	49 89 c6             	mov    %rax,%r14
   55fe6:	49 c1 ee 08          	shr    $0x8,%r14
   55fea:	e9 fe fc ff ff       	jmp    55ced <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x1ed>
   55fef:	48 8d 7c 24 40       	lea    0x40(%rsp),%rdi
   55ff4:	be 05 00 00 00       	mov    $0x5,%esi
   55ff9:	ba 10 00 00 00       	mov    $0x10,%edx
   55ffe:	4d 89 c6             	mov    %r8,%r14
   56001:	e8 9a dd ff ff       	call   53da0 <_RINvNvMs2_NtCsgFX3jaOk65H_5alloc7raw_vecINtB8_11RawVecInnerpE7reserve21do_reserve_and_handleNtNtBa_5alloc6GlobalECsHnFHAC5PMO_12rust_reality>
   56006:	4d 89 f0             	mov    %r14,%r8
   56009:	48 8b 54 24 10       	mov    0x10(%rsp),%rdx
   5600e:	8b 4c 24 0c          	mov    0xc(%rsp),%ecx
   56012:	4c 8b 4c 24 30       	mov    0x30(%rsp),%r9
   56017:	8b 74 24 08          	mov    0x8(%rsp),%esi
   5601b:	48 8b 7c 24 38       	mov    0x38(%rsp),%rdi
   56020:	48 8b 44 24 48       	mov    0x48(%rsp),%rax
   56025:	4c 8b 64 24 50       	mov    0x50(%rsp),%r12
   5602a:	49 89 c6             	mov    %rax,%r14
   5602d:	49 c1 ee 08          	shr    $0x8,%r14
   56031:	e9 d1 fc ff ff       	jmp    55d07 <_RNvNtNtNtCsHnFHAC5PMO_12rust_reality8protocol7nxr_udp4wire12encode_frame+0x207>
   56036:	bf 01 00 00 00       	mov    $0x1,%edi
   5603b:	4c 89 f6             	mov    %r14,%rsi
   5603e:	67 e8 2d 71 ff ff    	addr32 call 4d171 <_RNvNtCsgFX3jaOk65H_5alloc7raw_vec12handle_error>

Disassembly of section .init:

Disassembly of section .fini:

Disassembly of section .plt:
