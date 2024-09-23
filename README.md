# **Projeto de Criptografia em Java**

Este projeto é uma implementação de criptografia simétrica em Java, oferecendo suporte aos modos **AES/GCM** e **AES/CBC com HMAC**. Ele demonstra como criptografar e descriptografar dados de forma segura, seguindo as melhores práticas de segurança e os princípios de design de software (SOLID).

## **Sumário**

- [Descrição do Projeto](#descrição-do-projeto)
- [Tecnologias Utilizadas](#tecnologias-utilizadas)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Configuração do Ambiente](#configuração-do-ambiente)
- [Como Executar o Projeto](#como-executar-o-projeto)
    - [Compilação e Execução](#compilação-e-execução)
    - [Executando os Testes](#executando-os-testes)
- [Uso do Projeto](#uso-do-projeto)
    - [Criptografia e Descriptografia](#criptografia-e-descriptografia)
    - [Configuração das Chaves](#configuração-das-chaves)
- [Detalhes da Implementação](#detalhes-da-implementação)
    - [Gerenciamento de Chaves](#gerenciamento-de-chaves)
    - [Serviços de Criptografia](#serviços-de-criptografia)
- [Considerações de Segurança](#considerações-de-segurança)
- [Melhorias Futuras](#melhorias-futuras)
- [Licença](#licença)

---

## **Descrição do Projeto**

Este projeto demonstra como implementar criptografia simétrica segura em Java, fornecendo:

- **Dois modos de criptografia:**
    - **AES/GCM:** Modo de operação que fornece criptografia autenticada, garantindo confidencialidade e integridade dos dados.
    - **AES/CBC com HMAC:** Combina o modo AES/CBC para criptografia com HMAC-SHA256 para integridade dos dados.

- **Gerenciamento de chaves seguro:**
    - Carrega as chaves de criptografia e HMAC de variáveis de ambiente ou de um arquivo de propriedades seguro.
    - Gera novas chaves se não forem encontradas e as armazena para uso futuro.

- **Princípios de Design SOLID:**
    - Código modular, fácil de manter e estender.
    - Segue boas práticas de codificação e design orientado a objetos.

---

## **Tecnologias Utilizadas**

- **Java 8 ou superior**
- **Gradle 8.8** (sistema de build)
- **JUnit 5** (framework de testes unitários)

---

## **Estrutura do Projeto**
```
├── src
│   ├── main
│   │   └── java
│   │       └── com
│   │           └── ronaldsantos
│   │               ├── Main.java
│   │               ├── KeyManager.java
│   │               ├── KeyManagerImpl.java
│   │               ├── EncryptionService.java
│   │               ├── AesGcmEncryptionService.java
│   │               └── AesCbcEncryptionService.java
│   └── test
│       └── java
│           └── com
│               └── ronaldsantos
│                   ├── KeyManagerImplTest.java
│                   ├── AesGcmEncryptionServiceTest.java
│                   └── AesCbcEncryptionServiceTest.java
├── build.gradle.kts
├── settings.gradle.kts
└── README.md
```


---

## **Configuração do Ambiente**

1. **Pré-requisitos:**

    - **Java Development Kit (JDK) 8 ou superior**: Certifique-se de que o JDK está instalado e configurado no seu PATH.
    - **Gradle 8.8**: Instale o Gradle ou use o wrapper (`gradlew`) fornecido.

2. **Clonando o Repositório:**

   ```bash
   git clone https://github.com/seuusuario/seu-projeto.git
   cd seu-projeto
   ```

---

## **Como Executar o Projeto**

### **Compilação e Execução**

1. **Compilando o Projeto:**
    ```
   gradle build
   ```
2. **Executando a Aplicação**
   - A classe `Main` contém um exemplo de uso dos serviços de criptografia
       ```
      gradle run
      ```
   - Ou, para executar diretamente a classe `Main`:
     ```
     java -cp build/classes/java/main com.ronaldsantos.Main
     ```
### **Executando os Testes**

Para executar os testes unitários:
```
gradle test
```
Os resultados dos testes serão exibidos no console, e um relatório em HTML será gerado em `build/reports/tests/test/index.html`

---

## **Uso do Projeto**

### **Criptografia e Descriptografia**

A aplicação principal (`Main.java`) demonstra como usar os serviços de criptografia:

```java
public class Main {
    public static void main(String[] args) {
        try {
            KeyManager keyManager = new KeyManagerImpl();

            // Escolha o serviço de criptografia desejado
            EncryptionService encryptionService = new AesGcmEncryptionService(keyManager);
            // Ou use o modo AES/CBC com HMAC
            // EncryptionService encryptionService = new AesCbcEncryptionService(keyManager);

            String originalData = "Dados sensíveis que precisam ser protegidos";

            // Criptografa os dados
            String encryptedData = encryptionService.encrypt(originalData);
            System.out.println("Dados Criptografados: " + encryptedData);

            // Descriptografa os dados
            String decryptedData = encryptionService.decrypt(encryptedData);
            System.out.println("Dados Descriptografados: " + decryptedData);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## **Configuração das Chaves**

As chaves de criptografia são gerenciadas pela classe `KeyManagerImpl`, que segue a seguinte lógica:
1. **Variáveis de Ambiente:**
   - O `KeyManagerImpl` tenta carregar as chaves das variáveis de ambiente `ENCRYPTION_KEY` e `HMAC_KEY`.
   - As chaves devem estar codificadas em Base64.
2. **Arquivo de Propriedades:**
   - Se as chaves não estiverem nas variáveis de ambiente, tenta carregar do arquivo `key.properties`.
   - O arquivo deve estar localizado no diretório raiz do projeto e conter as chaves codificadas em Base64.
3. **Geração de Novas Chaves:**
   - Se as chaves não forem encontradas, novas chaves serão geradas.
   - As novas chaves serão salvas no arquivo `key.properties` para uso futuro.

**Exemplo de arquivo `key.properties`:**
```
ENCRYPTION_KEY=SuaChaveDeCriptografiaBase64
HMAC_KEY=SuaChaveHmacBase64
```

---

## **Detalhes da implementação**

### **Gerenciamento de Chaves**
- `KeyManager` (**Interface**): Define os métodos para obter as chaves de criptografia e HMAC.
- `KeyManagerImpl` (**Implementação**): Gerencia o carregamento e geração das chaves.

**Fluxo de Operação:**
- **Carregamento das Chaves:**
  - Verifica as variáveis de ambiente.
  - Se não encontradas, verifica o arquivo `keys.properties`.

### **Serviços de Criptografia**
- `EncryptionService` (**Interface**): Define os métodos de criptografia e descriptografia.
- `AesGcmEncryptionService` (**Implementação**): Implementa a criptografia AES/GCM.
- `AesCbcEncryptionService` (**Implementação**): Implementa a criptografia AES/CBC com HMAC-SHA256.

**Características:**
- **Thread Safety**: Usa `ThreadLocal` para armazenar instâncias de `Chiper` e `Mac`, garantindo segurança em ambientes multithreaded.
- **Segurança**: Implementa as melhores práticas, como uso de IVs aleatórios e verificação de integridade dos dados.

---

## **Considerações de Segurança**

- **Proteção das Chaves:**
  - As chaves devem ser mantidas em local seguro.
  - **Não** versionar o arquivo `keys.properties` ou expor as chaves em repositórios públicos.
  - Em ambientes de produção, considere o uso de um cofre de chaves seguro (ex: HashiCorp Vault, AWS KMS.).
- **Permissões de Arquivo:**
  - Defina permissões restritivas para o arquivo `keys.properties`.
  - Em sistemas Unix, use `chmod 600 keys.properties`.
- **Uso de HTTPS:**
  - Se a aplicação envolve comunicação em rede, utilize HTTPS para proteger os dados em trânsito.
- **Rotação de Chaves:**
  - Implementa um processo para rotacionar as chaves periodicamente.
- **Variáveis de Ambiente:**
  - Evite expor chaves em logs ou outputs da aplicação.

---

## **Melhorias Futuras**
- **Integração com Serviços de Gerenciamento de Chaves:**
  - Implemetar integração com serviços como AWS KMS, Azure Key Vault, etc.
- **Suporte a Outros Algoritmos:**
  - Adicionar suporte a outros algoritmos e modos de criptografia, como AES/CTR.
- **Implementação de Criptografia Assimétrica:**
  - Adicionar funcionalidades para criptografia assimétrica usando RSA ou ECC.
- **Melhoria nos Testes:**
  - Expandir a cobertura de testes unitários e adicionar testes de integração.
- **Documentação adicional:**
  - Fornecer exemplos mais detalhados e casos de uso específicos.

---

## **Licença**

Este projeto é licenciado sob os termos da licença MIT.

---

**Nota:** Este projeto é fornecido como um exemplo educacional e não deve ser usado em produção sem antes realizar uma análise completo de segurança e conformidade.
Sempre consulte um especialista em segurança antes de implementar sistemas de criptografia em ambientes críticos.

---

## **Referências**

- [Documentação do Java Cryptography Architecture(JCA)](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html)
- [Guia de Melhores Práticas em Criptografia](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Gradle User Manual](https://docs.gradle.org/current/userguide/userguide.html)
- [JUnit 5 Documentation](https://junit.org/junit5/docs/current/user-guide/)

---

**Obrigado por utilizar este projeto!** Se este repositório foi útil para você, considere deixar uma estrela no GitHub.