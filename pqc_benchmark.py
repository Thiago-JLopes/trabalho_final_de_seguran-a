"""
Replicação do artigo: Performance Analysis of Post-Quantum Cryptography
Algorithms for Digital Signature (Opiłka et al., 2024)

Requisitos:
pip install oqs
pip install matplotlib pandas numpy

Antes de rodar:
1. Instale liboqs: https://github.com/open-quantum-safe/liboqs
2. Instale liboqs-python: pip install liboqs-python
"""

import oqs
import time
import os
import hashlib
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple


class PQCBenchmark:
    """
    Classe para benchmark de algoritmos pós-quânticos de assinatura digital
    Baseado no artigo de Opiłka et al., 2024
    """

    def __init__(self):
        # Algoritmos testados no artigo (Tabela 1)
        self.algorithms = [
            "Dilithium2",
            "Dilithium3",
            "Dilithium5",
            "Falcon-512",
            "Falcon-1024",
            "SPHINCS+-SHA2-128f-simple",
            "SPHINCS+-SHA2-128s-simple",
            "SPHINCS+-SHA2-192f-simple",
            "SPHINCS+-SHA2-192s-simple",
            "SPHINCS+-SHA2-256f-simple",
            "SPHINCS+-SHA2-256s-simple",
        ]

        # Tamanhos de arquivo para teste (conforme artigo)
        self.file_sizes = {
            "10MB": 10 * 1024 * 1024,
            "100MB": 100 * 1024 * 1024,
            "1GB": 1024 * 1024 * 1024,
        }

        self.results = {"keygen": {}, "sign": {}, "verify": {}}

    def generate_test_file(self, size: int, filename: str) -> str:
        """
        Gera arquivo de teste com dados pseudo-aleatórios
        Similar ao comando dd usado no artigo
        """
        print(f"Gerando arquivo de teste: {filename} ({size / (1024*1024):.0f} MB)")

        with open(filename, "wb") as f:
            # Gera dados em chunks para não sobrecarregar memória
            chunk_size = 1024 * 1024  # 1MB chunks
            remaining = size

            while remaining > 0:
                write_size = min(chunk_size, remaining)
                f.write(os.urandom(write_size))
                remaining -= write_size

        return filename

    def benchmark_keygen(
        self, algorithm: str, iterations: int = 101
    ) -> Tuple[float, float]:
        """
        Benchmark de geração de par de chaves
        Conforme metodologia do artigo (101 iterações, primeira descartada)
        """
        times = []

        print(f"  Testando geração de chaves: {algorithm}")

        for i in range(iterations):
            try:
                signer = oqs.Signature(algorithm)

                start = time.perf_counter()
                public_key = signer.generate_keypair()
                end = time.perf_counter()

                # Descartar primeira iteração (conforme artigo)
                if i > 0:
                    times.append(end - start)

                # Limpar memória
                signer.free()

            except Exception as e:
                print(f"    Erro em {algorithm}: {e}")
                return 0, 0

        mean_time = np.mean(times)
        sem = np.std(times) / np.sqrt(len(times))  # Standard Error of Mean

        return mean_time, sem

    def benchmark_sign(
        self, algorithm: str, filename: str, iterations: int = 101
    ) -> Tuple[float, float]:
        """
        Benchmark de assinatura de arquivo
        """
        times = []

        print(f"  Testando assinatura: {algorithm} - {os.path.basename(filename)}")

        # Ler arquivo uma vez
        with open(filename, "rb") as f:
            file_data = f.read()

        for i in range(iterations):
            try:
                signer = oqs.Signature(algorithm)
                public_key = signer.generate_keypair()

                start = time.perf_counter()
                signature = signer.sign(file_data)
                end = time.perf_counter()

                # Descartar primeira iteração
                if i > 0:
                    times.append(end - start)

                signer.free()

            except Exception as e:
                print(f"    Erro em {algorithm}: {e}")
                return 0, 0

        mean_time = np.mean(times)
        sem = np.std(times) / np.sqrt(len(times))

        return mean_time, sem

    def benchmark_verify(
        self, algorithm: str, filename: str, iterations: int = 101
    ) -> Tuple[float, float]:
        """
        Benchmark de verificação de assinatura
        """
        times = []

        print(f"  Testando verificação: {algorithm} - {os.path.basename(filename)}")

        # Preparar dados
        with open(filename, "rb") as f:
            file_data = f.read()

        # Gerar chave e assinatura uma vez
        signer = oqs.Signature(algorithm)
        public_key = signer.generate_keypair()
        signature = signer.sign(file_data)

        for i in range(iterations):
            try:
                start = time.perf_counter()
                is_valid = signer.verify(file_data, signature, public_key)
                end = time.perf_counter()

                # Descartar primeira iteração
                if i > 0:
                    times.append(end - start)

            except Exception as e:
                print(f"    Erro em {algorithm}: {e}")
                signer.free()
                return 0, 0

        signer.free()

        mean_time = np.mean(times)
        sem = np.std(times) / np.sqrt(len(times))

        return mean_time, sem

    def run_full_benchmark(self, file_size_name: str = "10MB"):
        """
        Executa benchmark completo para um tamanho de arquivo
        """
        print(f"\n{'='*60}")
        print(f"INICIANDO BENCHMARK - {file_size_name}")
        print(f"{'='*60}\n")

        # Gerar arquivo de teste
        size = self.file_sizes[file_size_name]
        test_file = f"test_file_{file_size_name}.bin"
        self.generate_test_file(size, test_file)

        for algo in self.algorithms:
            print(f"\n[{algo}]")

            # 1. Key Generation
            mean, sem = self.benchmark_keygen(algo, iterations=101)
            if algo not in self.results["keygen"]:
                self.results["keygen"][algo] = {}
            self.results["keygen"][algo][file_size_name] = (mean, sem)

            # 2. Signing
            mean, sem = self.benchmark_sign(algo, test_file, iterations=101)
            if algo not in self.results["sign"]:
                self.results["sign"][algo] = {}
            self.results["sign"][algo][file_size_name] = (mean, sem)

            # 3. Verification
            mean, sem = self.benchmark_verify(algo, test_file, iterations=101)
            if algo not in self.results["verify"]:
                self.results["verify"][algo] = {}
            self.results["verify"][algo][file_size_name] = (mean, sem)

        # Limpar arquivo de teste
        os.remove(test_file)
        print(f"\n{'='*60}")
        print(f"BENCHMARK CONCLUÍDO - {file_size_name}")
        print(f"{'='*60}\n")

    def plot_results(self, operation: str, file_size: str):
        """
        Gera gráficos similares aos do artigo (Figuras 3-10)
        """
        fig, ax = plt.subplots(figsize=(12, 6))

        algorithms = []
        means = []
        sems = []

        for algo in self.algorithms:
            if algo in self.results[operation]:
                if file_size in self.results[operation][algo]:
                    mean, sem = self.results[operation][algo][file_size]
                    algorithms.append(algo)
                    means.append(mean * 1e5)  # Converter para 10^-5 s (como no artigo)
                    sems.append(sem * 1e5)

        # Criar barras com erro
        x_pos = np.arange(len(algorithms))
        bars = ax.bar(x_pos, means, yerr=sems, capsize=5, alpha=0.7, color="steelblue")

        # Configurar gráfico
        ax.set_xlabel("Algorithm", fontsize=12)
        ax.set_ylabel(f"Time [s × 10⁻⁵]", fontsize=12)

        title_map = {
            "keygen": "Average Key Generation Time",
            "sign": f"Average File Signing Time - {file_size}",
            "verify": f"Average File Verification Time - {file_size}",
        }
        ax.set_title(title_map[operation], fontsize=14, fontweight="bold")

        ax.set_xticks(x_pos)
        ax.set_xticklabels(algorithms, rotation=45, ha="right")
        ax.grid(axis="y", alpha=0.3)

        plt.tight_layout()
        plt.savefig(f"{operation}_{file_size}_benchmark.png", dpi=300)
        print(f"Gráfico salvo: {operation}_{file_size}_benchmark.png")
        plt.close()

    def export_results_table(self):
        """
        Exporta resultados em formato similar às Tabelas 3 e 4 do artigo
        """
        # Criar DataFrame
        data = []

        for algo in self.algorithms:
            row = {"Algorithm": algo}

            # Key generation
            if algo in self.results["keygen"]:
                for size in self.file_sizes.keys():
                    if size in self.results["keygen"][algo]:
                        mean, sem = self.results["keygen"][algo][size]
                        row[f"Keygen_{size}"] = f"{mean*1e5:.0f} ± {sem*1e5:.0f}"

            # Signing
            if algo in self.results["sign"]:
                for size in self.file_sizes.keys():
                    if size in self.results["sign"][algo]:
                        mean, sem = self.results["sign"][algo][size]
                        row[f"Sign_{size}"] = f"{mean*1e5:.0f} ± {sem*1e5:.0f}"

            # Verification
            if algo in self.results["verify"]:
                for size in self.file_sizes.keys():
                    if size in self.results["verify"][algo]:
                        mean, sem = self.results["verify"][algo][size]
                        row[f"Verify_{size}"] = f"{mean*1e5:.0f} ± {sem*1e5:.0f}"

            data.append(row)

        df = pd.DataFrame(data)

        # Salvar em CSV
        df.to_csv("pqc_benchmark_results.csv", index=False)
        print("\nResultados exportados para: pqc_benchmark_results.csv")

        # Mostrar resumo
        print("\n" + "=" * 80)
        print("RESUMO DOS RESULTADOS")
        print("=" * 80)
        print(df.to_string())


# =============================================================================
# EXEMPLO DE USO - TESTE RÁPIDO (apenas 10MB)
# =============================================================================


def quick_test():
    """
    Teste rápido com apenas alguns algoritmos e arquivo pequeno
    Para testar a instalação antes do benchmark completo
    """
    print("\n🚀 TESTE RÁPIDO - Verificação de Instalação")
    print("=" * 60)

    benchmark = PQCBenchmark()

    # Usar apenas 3 algoritmos para teste rápido
    benchmark.algorithms = ["Dilithium2", "Falcon-512", "SPHINCS+-SHA2-128f-simple"]

    # Teste com arquivo pequeno (10MB) e poucas iterações
    test_file = "quick_test.bin"
    benchmark.generate_test_file(10 * 1024 * 1024, test_file)

    for algo in benchmark.algorithms:
        print(f"\n[{algo}]")

        # Apenas 11 iterações para teste rápido (1 descartada + 10 válidas)
        mean, sem = benchmark.benchmark_keygen(algo, iterations=11)
        print(f"  Keygen: {mean*1000:.2f} ms")

        mean, sem = benchmark.benchmark_sign(algo, test_file, iterations=11)
        print(f"  Sign:   {mean*1000:.2f} ms")

        mean, sem = benchmark.benchmark_verify(algo, test_file, iterations=11)
        print(f"  Verify: {mean*1000:.2f} ms")

    os.remove(test_file)
    print("\n✅ Teste concluído! Sistema funcionando corretamente.")


# =============================================================================
# BENCHMARK COMPLETO (como no artigo)
# =============================================================================


def full_benchmark():
    """
    Benchmark completo replicando o artigo
    ATENÇÃO: Pode levar várias horas!
    """
    benchmark = PQCBenchmark()

    # Executar para cada tamanho de arquivo
    for size_name in ["10MB", "100MB", "1GB"]:
        benchmark.run_full_benchmark(size_name)

        # Gerar gráficos
        benchmark.plot_results("keygen", size_name)
        benchmark.plot_results("sign", size_name)
        benchmark.plot_results("verify", size_name)

    # Exportar tabela de resultados
    benchmark.export_results_table()

    print("\n🎉 BENCHMARK COMPLETO FINALIZADO!")


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    import sys

    print(
        """
    ╔══════════════════════════════════════════════════════════════╗
    ║  Benchmark de Criptografia Pós-Quântica                     ║
    ║  Replicação: Opiłka et al., 2024                           ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    )

    print("\nEscolha uma opção:")
    print("1 - Teste Rápido (3 algoritmos, 10MB, ~5 min)")
    print("2 - Benchmark Completo (todos algoritmos, 10MB/100MB/1GB, ~várias horas)")
    print("0 - Sair")

    choice = input("\nOpção: ").strip()

    if choice == "1":
        quick_test()
    elif choice == "2":
        confirm = input("\n⚠️  Benchmark completo pode levar HORAS. Continuar? (s/n): ")
        if confirm.lower() == "s":
            full_benchmark()
        else:
            print("Cancelado.")
    else:
        print("Saindo...")
