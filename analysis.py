import pandas as pd
import matplotlib.pyplot as plt
import os
import altair as alt
import sys

# ***** CONFIGURATION *****
OUTPUT_DIR = "analysis_results"
# ***** END CONFIGURATION *****

def analyze_dataset(csv_file):
    # Extrair o nome base do arquivo CSV para criar a pasta de saída
    dataset_name = os.path.splitext(os.path.basename(csv_file))[0]
    dataset_output_dir = os.path.join(OUTPUT_DIR, dataset_name)
    os.makedirs(dataset_output_dir, exist_ok=True)

    # Criar arquivo de log para salvar os resultados do terminal
    log_file_path = os.path.join(dataset_output_dir, f"{dataset_name}_analysis.txt")
    log_file = open(log_file_path, "w")

    # Carregar o arquivo CSV
    df = pd.read_csv(csv_file, sep=',', encoding='latin1')

    # Convert 'published' para objetos datetime
    df['published'] = pd.to_datetime(df['published'], errors='coerce')

    # Extrair ano, mês, dia da semana e trimestre
    df['year'] = df['published'].dt.year
    df['month'] = df['published'].dt.month
    df['day_of_week'] = df['published'].dt.day_name()
    df['quarter'] = df['published'].dt.quarter

    # --- Análise Descritiva ---
    log_file.write(f"Análise do dataset: {csv_file}\n\n")

    # 1. Total de Vulnerabilidades
    total_vulnerabilities = len(df)
    log_file.write(f"Total de Vulnerabilidades: {total_vulnerabilities}\n")

    # 2. Distribuição por Fornecedor
    vendor_counts = df['vendor'].value_counts()
    log_file.write("\nDistribuição de Vulnerabilidades por Fornecedor:\n")
    log_file.write(vendor_counts.to_string() + "\n")

    # 3. Distribuição por Ano
    vulnerabilities_per_year = df['year'].value_counts().sort_index()
    log_file.write("\nDistribuição de Vulnerabilidades por Ano:\n")
    log_file.write(vulnerabilities_per_year.to_string() + "\n")

    # 4. Estatísticas Descritivas de CVSS Scores
    log_file.write("\nEstatísticas Descritivas de CVSS Scores:\n")
    log_file.write(df['cvss_score'].describe().to_string() + "\n")

    # 5. Top 5 Categorias CWE Mais Frequentes
    cwe_counts = df['cwe_category'].value_counts().head(5)
    log_file.write("\nTop 5 Categorias CWE Mais Frequentes:\n")
    log_file.write(cwe_counts.to_string() + "\n")

    # 6. Correlação entre Severidade e Fornecedor
    contingency_table = pd.crosstab(df['vendor'], df['severity'])
    log_file.write("\nTabela de Contingência entre Severidade e Fornecedor:\n")
    log_file.write(contingency_table.to_string() + "\n")

    # --- Gerar Gráficos ---
    df['cvss_score'] = df['cvss_score'] / 10
    df['vendor'] = df['vendor'].str.upper()
    vendor_counts.index = vendor_counts.index.str.upper()
    font_size = 14

    # Gráfico 1: Vulnerabilidades por Fornecedor
    plt.figure(figsize=(10, 6))
    vendor_counts.plot(kind='bar')
    plt.title("Distribuição de Vulnerabilidades por Fornecedor", fontsize=font_size)
    plt.xlabel("Fornecedor", fontsize=font_size)
    plt.ylabel("Número de Vulnerabilidades", fontsize=font_size)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig(os.path.join(dataset_output_dir, "vulnerabilities_by_vendor.png"))
    plt.close()

    # Gráfico 2: Vulnerabilidades por Ano
    plt.figure(figsize=(10, 6))
    vulnerabilities_per_year.plot(kind='line', marker='o')
    plt.title("Distribuição de Vulnerabilidades por Ano", fontsize=font_size)
    plt.xlabel("Ano", fontsize=font_size)
    plt.ylabel("Número de Vulnerabilidades", fontsize=font_size)
    plt.grid(True)
    plt.savefig(os.path.join(dataset_output_dir, "vulnerabilities_by_year.png"))
    plt.close()

    # Gráfico 3: Distribuição de CVSS Scores
    plt.figure(figsize=(10, 6))
    plt.hist(df['cvss_score'], bins=10, edgecolor='black')
    plt.title("Distribuição de CVSS Scores", fontsize=font_size)
    plt.xlabel("CVSS Score", fontsize=font_size)
    plt.ylabel("Frequência", fontsize=font_size)
    plt.savefig(os.path.join(dataset_output_dir, "cvss_distribution.png"))
    plt.close()

    # Gráfico 4: Top 5 Categorias CWE
    plt.figure(figsize=(8, 8))
    plt.pie(cwe_counts.values, labels=cwe_counts.index, autopct='%1.1f%%', startangle=90)
    plt.title("Top 5 Categorias CWE Mais Frequentes", fontsize=font_size)
    plt.savefig(os.path.join(dataset_output_dir, "top_5_cwe.png"))
    plt.close()

    # Fechar o arquivo de log
    log_file.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python analysis.py <arquivo_csv1> <arquivo_csv2> ...")
        sys.exit(1)

    csv_files = sys.argv[1:]
    for csv_file in csv_files:
        analyze_dataset(csv_file)