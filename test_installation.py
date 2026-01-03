import oqs

# Listar algoritmos disponíveis
print("Algoritmos de assinatura disponíveis:")
for i, sig in enumerate(oqs.get_enabled_sig_mechanisms(), 1):
    print(f"{i:2d}. {sig}")

# Teste básico com Dilithium2
print("\nTestando Dilithium2...")
signer = oqs.Signature("Dilithium2")

# Gerar par de chaves
public_key = signer.generate_keypair()
print(f"✓ Chave pública gerada: {len(public_key)} bytes")

# Assinar mensagem
message = b"Hello, Post-Quantum World!"
signature = signer.sign(message)
print(f"✓ Assinatura gerada: {len(signature)} bytes")

# Verificar assinatura
is_valid = signer.verify(message, signature, public_key)
print(f"✓ Assinatura válida: {is_valid}")

signer.free()
print("\n✅ Instalação funcionando perfeitamente!")
