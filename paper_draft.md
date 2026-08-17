# Verifiable and Pairing-Free Certificateless Searchable Encryption with Complete Keyword-Guessing Attack Resistance

## 1. Abstract
The rapid proliferation of Mobile and Medical Internet of Things (MIoT) has driven the adoption of cloud servers for outsourced data storage. However, preserving data privacy while maintaining searchability remains a critical challenge. Certificateless Searchable Encryption (CL-SE) eliminates the certificate management overhead of traditional PKI and the key escrow problem of Identity-Based Cryptography. Yet, existing CL-SE schemes suffer from three major limitations: (1) heavy reliance on computationally expensive bilinear pairings; (2) vulnerability to Outside Keyword-Guessing Attacks (OKGA) when trapdoors are intercepted; and (3) a lack of verifiable search mechanisms, forcing users to blindly trust that the "honest-but-curious" cloud server has returned complete results. In this paper, we propose a novel pairing-free, verifiable certificateless searchable encryption scheme designed for IoT-cloud environments. The proposed scheme achieves simultaneous resistance against both Inside and Outside Keyword-Guessing Attacks (IKGA/OKGA) through a server-bound trapdoor blinding mechanism. Furthermore, we integrate a Merkle Hash Tree (MHT) structure to guarantee search completeness and soundness. Formal security proofs in the random oracle model demonstrate that the scheme's security reduces to the hard Computational Diffie-Hellman (CDH) problem. Theoretical performance analysis confirms that the proposed pairing-free construction is highly efficient and scalable, making it ideally suited for deployment in resource-constrained MIoT networks.

## 2. Introduction
**2.1 Background and Motivation**
The integration of Internet of Things (IoT) devices with cloud computing paradigms has revolutionized data processing, particularly in domains such as electronic healthcare and smart cities. Because IoT devices possess limited storage and computational capacity, outsourcing encrypted data to external cloud servers has become standard practice. However, outsourcing introduces severe privacy concerns. To retrieve specific files without decrypting the entire database, Searchable Encryption (SE) was introduced, allowing a cloud server to test encrypted keywords against encrypted trapdoors. 

While early Public Key Encryption with Keyword Search (PEKS) schemes relied on traditional Public Key Infrastructure (PKI), the burden of managing and revoking digital certificates is prohibitively expensive for IoT networks. Identity-Based SE (IB-SE) resolved certificate management but introduced the key escrow problem, where a central Private Key Generator knows all user keys. Certificateless Searchable Encryption (CL-SE) solves both issues by splitting the private key between a Key Generation Center (KGC) and the user.

**2.2 Problem Statement**
Despite the architectural advantages of CL-SE, deploying current schemes in dynamic IoT environments presents three unsolved challenges:
1.  **Computational Bottlenecks:** The vast majority of existing CL-SE schemes rely on bilinear pairing operations over elliptic curves to establish shared secrets during the search phase. Bilinear pairings are notoriously resource-intensive and drain the batteries of lightweight IoT sensors.
2.  **Keyword Guessing Attacks (KGA):** Because the space of keywords is inherently low-entropy (e.g., dictionary words, medical terms), SE schemes are highly susceptible to offline guessing attacks. While some recent schemes protect against a malicious server (Inside KGA), they often fail to protect against an external eavesdropper who intercepts the trapdoor (Outside KGA).
3.  **Lack of Verifiability:** Standard SE assumes the cloud server is "honest-but-curious." In reality, a commercially motivated cloud server might execute a search partially to save CPU cycles, returning incomplete results. Users currently have no cryptographic method to verify the soundness and completeness of the returned data.

**2.3 Contributions**
To address these gaps, we propose a Verifiable, Pairing-Free Certificateless Searchable Encryption scheme with complete KGA resistance. Our core contributions are:
1.  **A Pairing-Free Construction:** We design a novel CL-SE architecture that utilizes only lightweight Elliptic Curve scalar multiplications, entirely eliminating bilinear pairings.
2.  **Simultaneous IKGA and OKGA Resistance:** We introduce a dual-blinding trapdoor generation mechanism that binds the search token to the specific public key of the cloud server, ensuring that neither an internal server nor an external eavesdropper can launch offline dictionary attacks.
3.  **Built-in Verifiability:** We integrate a Merkle Hash Tree (MHT) verification layer into the index generation phase. The cloud server must provide a verifiable sibling path alongside search results, guaranteeing search completeness.
4.  **Formal Security and Efficiency:** We provide rigorous security proofs reducing the scheme's hardness to the CDH problem and demonstrate via theoretical analysis that the scheme drastically reduces computational overhead compared to state-of-the-art pairing-based alternatives.

## 5. The Proposed Construction (Scheme X)
### 5.1. Global Setup (`Setup`)
The Key Generation Center (KGC) runs this algorithm to initialize the system.
*   Choose a cyclic additive group $\mathbb{G}$ of prime order $q$ generated by a point $P$ on an elliptic curve.
*   Choose a master secret key $s \in \mathbb{Z}_q^*$ randomly, and compute the master public key $P_{pub} = sP$.
*   Choose cryptographic hash functions: $H_1, H_2, H_3, H_4$.
*   Publish public parameters $params = \{\mathbb{G}, q, P, P_{pub}, H_1, H_2, H_3, H_4\}$. Keep $s$ secret.

### 5.2. Key Generation (Certificateless)
**`PartialKeyExtract(ID)`:** KGC computes $D_{ID} = s \cdot H_1(ID)$.
**`SetSecretValue(ID)`:** User chooses random $x_{ID} \in \mathbb{Z}_q^*$.
**`SetPublicKey(ID)`:** User computes $PK_{ID} = x_{ID}P$.

### 5.3. Encryption & Index Generation (`Encrypt`)
Data Owner (DO) encrypts keyword $W$ for Data User (DU):
*   Choose random $r \in \mathbb{Z}_q^*$, compute $R = rP$.
*   Compute shared secret $K_{DO-DU} = r \cdot PK_{DU}$.
*   Compute index: $C_W = H_4(W, K_{DO-DU}, R) \oplus H_2(r \cdot P_{pub}, R)$.
*   Upload $(R, C_W)$ and Merkle Hash Tree root $Root_{MHT}$.

### 5.4. Trapdoor Generation (`Trapdoor`)
Data User (DU) searches for $W'$ via Cloud Server (CS):
*   Choose random $t \in \mathbb{Z}_q^*$, compute $T_1 = tP$.
*   Compute core trapdoor: $T_2 = H_4(W', t \cdot PK_{DO}, T_1)$.
*   Secure against KGA: $T_3 = T_2 \oplus H_2(t \cdot PK_{CS}, T_1)$.
*   Send $T_w = (T_1, T_3)$ to CS.

### 5.5. Search / Test (`Search`)
Cloud Server (CS) tests $T_w$ against index $I = (R, C_W)$:
*   Unblind trapdoor using $SK_{CS}$: $T_2^* = T_3 \oplus H_2(x_{CS} \cdot T_1, T_1)$.
*   Check if: $C_W \oplus H_2(s \cdot R, R) \stackrel{?}{=} T_2^*$.

## 6. Formal Security Analysis
*   **Theorem 1:** The proposed scheme is IND-CKA secure against both Type I and Type II adversaries in the random oracle model, assuming the CDH problem is hard in $\mathbb{G}$.
*   **Theorem 2:** Scheme X is IND-IKGA secure in the random oracle model, assuming the CDH problem is hard.
*   **Theorem 3:** Scheme X is IND-OKGA secure in the random oracle model, assuming the CDH problem is hard.
*   **Theorem 4:** Scheme X provides verifiable search completeness and soundness, assuming the underlying Merkle Hash Tree (MHT) utilizes a collision-resistant hash function.

## 7. Performance Evaluation
| Scheme | Paradigm | Setup | Encrypt | Trapdoor | Search | KGA Resistance | Verifiable |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Lu et al. [Ref 1]** | CL-PKC | $1 T_m$ | $2 T_p + 4 T_m + 2 T_h$ | $1 T_p + 3 T_m + 2 T_h$ | $2 T_p + 1 T_m$ | IKGA + OKGA | No |
| **Elhabob et al. [Ref 2]** | CL-PKC | $1 T_m$ | $5 T_m$ | $0$ (Auth 1) | $4 T_p$ | IKGA only | No |
| **Liu et al. [Ref 3]** | CL-PKC | $1 T_m$ | $4 T_m + 2 T_h$ | $3 T_m + 2 T_h$ | $6 T_m$ | IKGA + OKGA | No |
| **Proposed Scheme X** | CL-PKC | $1 T_m$ | $2 T_m + 1 T_h$ | $2 T_m + 1 T_h$ | $2 T_m$ | IKGA + OKGA | **Yes** |
