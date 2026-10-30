
/home/jacek/.cache/rr-v230-code-inspection-1c1930f/rust-reality-symbols:     file format elf64-x86-64


Disassembly of section .text:

0000000000527880 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition>:
  527880:	55                   	push   %rbp
  527881:	41 57                	push   %r15
  527883:	41 56                	push   %r14
  527885:	41 55                	push   %r13
  527887:	41 54                	push   %r12
  527889:	53                   	push   %rbx
  52788a:	48 81 ec 98 01 00 00 	sub    $0x198,%rsp
  527891:	48 89 fb             	mov    %rdi,%rbx
  527894:	80 be ce 01 00 00 02 	cmpb   $0x2,0x1ce(%rsi)
  52789b:	0f 85 1c 01 00 00    	jne    5279bd <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x13d>
  5278a1:	49 89 f6             	mov    %rsi,%r14
  5278a4:	49 bf 00 00 00 00 00 	movabs $0x8000000000000000,%r15
  5278ab:	00 00 80 
  5278ae:	48 81 c6 d8 00 00 00 	add    $0xd8,%rsi
  5278b5:	48 8d 7c 24 18       	lea    0x18(%rsp),%rdi
  5278ba:	ba c0 00 00 00       	mov    $0xc0,%edx
  5278bf:	ff 15 63 b7 28 00    	call   *0x28b763(%rip)        # 7b3028 <memcpy@GLIBC_2.14>
  5278c5:	49 8d 47 01          	lea    0x1(%r15),%rax
  5278c9:	49 89 86 d8 00 00 00 	mov    %rax,0xd8(%r14)
  5278d0:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
  5278d5:	48 85 c0             	test   %rax,%rax
  5278d8:	0f 88 e8 00 00 00    	js     5279c6 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x146>
  5278de:	4c 8d bc 24 d8 00 00 	lea    0xd8(%rsp),%r15
  5278e5:	00 
  5278e6:	48 8d 74 24 18       	lea    0x18(%rsp),%rsi
  5278eb:	ba c0 00 00 00       	mov    $0xc0,%edx
  5278f0:	4c 89 ff             	mov    %r15,%rdi
  5278f3:	ff 15 2f b7 28 00    	call   *0x28b72f(%rip)        # 7b3028 <memcpy@GLIBC_2.14>
  5278f9:	48 8d 7c 24 18       	lea    0x18(%rsp),%rdi
  5278fe:	4c 89 fe             	mov    %r15,%rsi
  527901:	e8 ea e1 02 00       	call   555af0 <<rust_reality::protocol::reality::tls13::application_io::TlsApplicationReader<tokio::net::tcp::split_owned::OwnedReadHalf>>::into_inner_with_pending>
  527906:	48 8b 44 24 18       	mov    0x18(%rsp),%rax
  52790b:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
  527910:	48 8b 44 24 20       	mov    0x20(%rsp),%rax
  527915:	48 89 04 24          	mov    %rax,(%rsp)
  527919:	4c 8b 7c 24 28       	mov    0x28(%rsp),%r15
  52791e:	4c 8b 64 24 30       	mov    0x30(%rsp),%r12
  527923:	4c 89 64 24 10       	mov    %r12,0x10(%rsp)
  527928:	4d 8b ae a8 00 00 00 	mov    0xa8(%r14),%r13
  52792f:	49 8b ae b8 00 00 00 	mov    0xb8(%r14),%rbp
  527936:	4c 89 e8             	mov    %r13,%rax
  527939:	48 29 e8             	sub    %rbp,%rax
  52793c:	49 39 c7             	cmp    %rax,%r15
  52793f:	0f 87 70 01 00 00    	ja     527ab5 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x235>
  527945:	4d 85 ff             	test   %r15,%r15
  527948:	74 17                	je     527961 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0xe1>
  52794a:	49 8b be b0 00 00 00 	mov    0xb0(%r14),%rdi
  527951:	48 01 ef             	add    %rbp,%rdi
  527954:	48 8b 34 24          	mov    (%rsp),%rsi
  527958:	4c 89 fa             	mov    %r15,%rdx
  52795b:	ff 15 c7 b6 28 00    	call   *0x28b6c7(%rip)        # 7b3028 <memcpy@GLIBC_2.14>
  527961:	4c 01 fd             	add    %r15,%rbp
  527964:	45 31 ff             	xor    %r15d,%r15d
  527967:	b8 00 80 00 00       	mov    $0x8000,%eax
  52796c:	48 29 e8             	sub    %rbp,%rax
  52796f:	4c 0f 43 f8          	cmovae %rax,%r15
  527973:	49 89 ae b8 00 00 00 	mov    %rbp,0xb8(%r14)
  52797a:	4c 89 e8             	mov    %r13,%rax
  52797d:	48 29 e8             	sub    %rbp,%rax
  527980:	49 39 c7             	cmp    %rax,%r15
  527983:	0f 87 be 00 00 00    	ja     527a47 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x1c7>
  527989:	49 8d be d8 00 00 00 	lea    0xd8(%r14),%rdi
  527990:	48 8b 07             	mov    (%rdi),%rax
  527993:	49 bf 00 00 00 00 00 	movabs $0x8000000000000000,%r15
  52799a:	00 00 80 
  52799d:	49 8d 0c 07          	lea    (%r15,%rax,1),%rcx
  5279a1:	48 ff c1             	inc    %rcx
  5279a4:	48 c1 f8 3f          	sar    $0x3f,%rax
  5279a8:	48 21 c8             	and    %rcx,%rax
  5279ab:	48 83 f8 01          	cmp    $0x1,%rax
  5279af:	74 39                	je     5279ea <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x16a>
  5279b1:	48 85 c0             	test   %rax,%rax
  5279b4:	75 4a                	jne    527a00 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x180>
  5279b6:	e8 f5 6b eb ff       	call   3de5b0 <core::ptr::drop_glue::<rust_reality::protocol::reality::tls13::application_io::TlsApplicationReader<tokio::net::tcp::split_owned::OwnedReadHalf>>>
  5279bb:	eb 43                	jmp    527a00 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x180>
  5279bd:	48 c7 03 ff ff ff ff 	movq   $0xffffffffffffffff,(%rbx)
  5279c4:	eb 6c                	jmp    527a32 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x1b2>
  5279c6:	4c 39 f8             	cmp    %r15,%rax
  5279c9:	75 16                	jne    5279e1 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x161>
  5279cb:	48 8b 44 24 20       	mov    0x20(%rsp),%rax
  5279d0:	f0 48 ff 08          	lock decq (%rax)
  5279d4:	75 0b                	jne    5279e1 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x161>
  5279d6:	48 8d 7c 24 20       	lea    0x20(%rsp),%rdi
  5279db:	ff 15 97 da 28 00    	call   *0x28da97(%rip)        # 7b5478 <_DYNAMIC+0x2688>
  5279e1:	48 c7 03 0d 00 00 00 	movq   $0xd,(%rbx)
  5279e8:	eb 48                	jmp    527a32 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x1b2>
  5279ea:	49 8d be e0 00 00 00 	lea    0xe0(%r14),%rdi
  5279f1:	48 8b 07             	mov    (%rdi),%rax
  5279f4:	f0 48 ff 08          	lock decq (%rax)
  5279f8:	75 06                	jne    527a00 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x180>
  5279fa:	ff 15 78 da 28 00    	call   *0x28da78(%rip)        # 7b5478 <_DYNAMIC+0x2688>
  527a00:	4d 89 be d8 00 00 00 	mov    %r15,0xd8(%r14)
  527a07:	4d 89 a6 e0 00 00 00 	mov    %r12,0xe0(%r14)
  527a0e:	49 8b 86 80 03 00 00 	mov    0x380(%r14),%rax
  527a15:	c6 40 11 01          	movb   $0x1,0x11(%rax)
  527a19:	48 c7 03 ff ff ff ff 	movq   $0xffffffffffffffff,(%rbx)
  527a20:	48 83 7c 24 08 00    	cmpq   $0x0,0x8(%rsp)
  527a26:	74 0a                	je     527a32 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x1b2>
  527a28:	48 8b 3c 24          	mov    (%rsp),%rdi
  527a2c:	ff 15 96 b6 28 00    	call   *0x28b696(%rip)        # 7b30c8 <free@GLIBC_2.2.5>
  527a32:	48 89 d8             	mov    %rbx,%rax
  527a35:	48 81 c4 98 01 00 00 	add    $0x198,%rsp
  527a3c:	5b                   	pop    %rbx
  527a3d:	41 5c                	pop    %r12
  527a3f:	41 5d                	pop    %r13
  527a41:	41 5e                	pop    %r14
  527a43:	41 5f                	pop    %r15
  527a45:	5d                   	pop    %rbp
  527a46:	c3                   	ret
  527a47:	49 01 ef             	add    %rbp,%r15
  527a4a:	49 8b 96 b0 00 00 00 	mov    0xb0(%r14),%rdx
  527a51:	48 8d 7c 24 18       	lea    0x18(%rsp),%rdi
  527a56:	41 b8 01 00 00 00    	mov    $0x1,%r8d
  527a5c:	41 b9 01 00 00 00    	mov    $0x1,%r9d
  527a62:	4c 89 ee             	mov    %r13,%rsi
  527a65:	4c 89 f9             	mov    %r15,%rcx
  527a68:	e8 43 74 02 00       	call   54eeb0 <<alloc::raw_vec::RawVecInner>::finish_grow>
  527a6d:	83 7c 24 18 01       	cmpl   $0x1,0x18(%rsp)
  527a72:	75 29                	jne    527a9d <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x21d>
  527a74:	48 c7 03 10 00 00 00 	movq   $0x10,(%rbx)
  527a7b:	48 b8 03 00 00 00 26 	movabs $0x2600000003,%rax
  527a82:	00 00 00 
  527a85:	48 89 43 08          	mov    %rax,0x8(%rbx)
  527a89:	f0 49 ff 0c 24       	lock decq (%r12)
  527a8e:	75 90                	jne    527a20 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x1a0>
  527a90:	48 8d 7c 24 10       	lea    0x10(%rsp),%rdi
  527a95:	ff 15 dd d9 28 00    	call   *0x28d9dd(%rip)        # 7b5478 <_DYNAMIC+0x2688>
  527a9b:	eb 83                	jmp    527a20 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x1a0>
  527a9d:	48 8b 44 24 20       	mov    0x20(%rsp),%rax
  527aa2:	49 89 86 b0 00 00 00 	mov    %rax,0xb0(%r14)
  527aa9:	4d 89 be a8 00 00 00 	mov    %r15,0xa8(%r14)
  527ab0:	e9 d4 fe ff ff       	jmp    527989 <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0x109>
  527ab5:	49 8d be a8 00 00 00 	lea    0xa8(%r14),%rdi
  527abc:	b9 01 00 00 00       	mov    $0x1,%ecx
  527ac1:	41 b8 01 00 00 00    	mov    $0x1,%r8d
  527ac7:	48 89 ee             	mov    %rbp,%rsi
  527aca:	4c 89 fa             	mov    %r15,%rdx
  527acd:	e8 fe dd ef ff       	call   4258d0 <<alloc::raw_vec::RawVecInner<_>>::reserve::do_reserve_and_handle::<alloc::alloc::Global>>
  527ad2:	4d 8b ae a8 00 00 00 	mov    0xa8(%r14),%r13
  527ad9:	49 8b ae b8 00 00 00 	mov    0xb8(%r14),%rbp
  527ae0:	e9 65 fe ff ff       	jmp    52794a <<rust_reality::client::vision_io::VisionIo>::finish_read_transition+0xca>
  527ae5:	cc                   	int3
  527ae6:	cc                   	int3
  527ae7:	cc                   	int3
  527ae8:	cc                   	int3
  527ae9:	cc                   	int3
  527aea:	cc                   	int3
  527aeb:	cc                   	int3
  527aec:	cc                   	int3
  527aed:	cc                   	int3
  527aee:	cc                   	int3
  527aef:	cc                   	int3
