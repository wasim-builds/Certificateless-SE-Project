use k256::{
    elliptic_curve::sec1::ToEncodedPoint,
    ProjectivePoint, Scalar, SecretKey,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

/// H1: Hash Identity to a Scalar
pub fn hash_1(id: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(id);
    let result = hasher.finalize();
    // In a production environment, use hash-to-curve/scalar properly.
    // Here we construct a scalar directly from bytes for the simulation.
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Scalar::from_bytes_reduced(&bytes.into())
}

/// H2: Hash two Group Elements to a 256-bit string (XOR mask)
pub fn hash_2(p1: &ProjectivePoint, p2: &ProjectivePoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(p1.to_encoded_point(true).as_bytes());
    hasher.update(p2.to_encoded_point(true).as_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    result
}

/// H4: Hash Keyword and two Group Elements to a 256-bit core token
pub fn hash_4(keyword: &[u8], k_do_du: &ProjectivePoint, r: &ProjectivePoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(keyword);
    hasher.update(k_do_du.to_encoded_point(true).as_bytes());
    hasher.update(r.to_encoded_point(true).as_bytes());
    let mut result = [0u8; 32];
    result.copy_from_slice(&hasher.finalize());
    result
}

/// XOR two 32-byte arrays
pub fn xor_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut res = [0u8; 32];
    for i in 0..32 {
        res[i] = a[i] ^ b[i];
    }
    res
}

pub struct KGC {
    pub master_secret: Scalar,
    pub master_public: ProjectivePoint,
}

impl KGC {
    pub fn setup() -> Self {
        let master_secret = SecretKey::random(&mut OsRng).to_nonzero_scalar();
        let master_public = ProjectivePoint::GENERATOR * *master_secret;
        Self {
            master_secret: *master_secret,
            master_public,
        }
    }

    pub fn extract_partial_key(&self, id: &[u8]) -> Scalar {
        let h1_id = hash_1(id);
        self.master_secret * h1_id
    }
}

pub struct UserKeys {
    pub partial_secret: Scalar,
    pub user_secret: Scalar,
    pub pk_1: ProjectivePoint, // user_secret * G
    pub pk_2: ProjectivePoint, // partial_secret * G
}

impl UserKeys {
    pub fn generate(kgc: &KGC, id: &[u8]) -> Self {
        let partial_secret = kgc.extract_partial_key(id);
        let user_secret = SecretKey::random(&mut OsRng).to_nonzero_scalar();
        
        Self {
            partial_secret,
            user_secret: *user_secret,
            pk_1: ProjectivePoint::GENERATOR * *user_secret,
            pk_2: ProjectivePoint::GENERATOR * partial_secret,
        }
    }
}

/// Data Owner encrypts a keyword index
pub fn encrypt_index(keyword: &[u8], du_pk1: &ProjectivePoint, kgc_pub: &ProjectivePoint) -> (ProjectivePoint, [u8; 32]) {
    let r_scalar = SecretKey::random(&mut OsRng).to_nonzero_scalar();
    let r_point = ProjectivePoint::GENERATOR * *r_scalar;
    
    // Shared secret bridging DO and DU
    let k_do_du = du_pk1 * *r_scalar;
    
    let alpha = hash_4(keyword, &k_do_du, &r_point);
    let blind = hash_2(&(kgc_pub * *r_scalar), &r_point);
    
    let c_w = xor_bytes(&alpha, &blind);
    
    (r_point, c_w)
}

/// Data User generates a trapdoor for a keyword
pub fn generate_trapdoor(keyword: &[u8], do_pk1: &ProjectivePoint, cs_pk1: &ProjectivePoint, du_secret: &Scalar) -> (ProjectivePoint, [u8; 32]) {
    let t_scalar = SecretKey::random(&mut OsRng).to_nonzero_scalar();
    let t1 = ProjectivePoint::GENERATOR * *t_scalar;
    
    // Core token
    let k_t = do_pk1 * *t_scalar;
    let t2 = hash_4(keyword, &k_t, &t1);
    
    // Bind to Cloud Server to prevent OKGA
    let blind = hash_2(&(cs_pk1 * *t_scalar), &t1);
    let t3 = xor_bytes(&t2, &blind);
    
    (t1, t3)
}

/// Cloud Server tests if the trapdoor matches the index
pub fn search(t1: &ProjectivePoint, t3: &[u8; 32], r_point: &ProjectivePoint, c_w: &[u8; 32], cs_secret: &Scalar, kgc_master: &Scalar) -> bool {
    // Server unblinds the trapdoor
    let blind_server = hash_2(&(t1 * cs_secret), t1);
    let t2_star = xor_bytes(t3, &blind_server);
    
    // Server unblinds the index
    // Note: In real scheme, the server uses d_CS or delegated token instead of kgc_master directly, 
    // but mathematically s * R is what is needed to unblind.
    let blind_index = hash_2(&(r_point * kgc_master), r_point);
    let alpha_star = xor_bytes(c_w, &blind_index);
    
    t2_star == alpha_star
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cl_se_full_workflow() {
        let kgc = KGC::setup();
        
        let do_keys = UserKeys::generate(&kgc, b"DataOwner@iot.net");
        let du_keys = UserKeys::generate(&kgc, b"DataUser@doctor.org");
        let cs_keys = UserKeys::generate(&kgc, b"CloudServer@aws.com");
        
        let keyword = b"CONFIDENTIAL_MEDICAL_RECORD";
        
        // 1. Data Owner Encrypts Index
        let (r_point, c_w) = encrypt_index(keyword, &du_keys.pk_1, &kgc.master_public);
        
        // 2. Data User generates Trapdoor
        let (t1, t3) = generate_trapdoor(keyword, &do_keys.pk_1, &cs_keys.pk_1, &du_keys.user_secret);
        
        // 3. Cloud Server performs Search
        let is_match = search(&t1, &t3, &r_point, &c_w, &cs_keys.user_secret, &kgc.master_secret);
        assert!(is_match, "Valid keyword should produce a match");
        
        // 4. Test wrong keyword
        let wrong_keyword = b"PUBLIC_LOGS";
        let (t1_wrong, t3_wrong) = generate_trapdoor(wrong_keyword, &do_keys.pk_1, &cs_keys.pk_1, &du_keys.user_secret);
        let is_match_wrong = search(&t1_wrong, &t3_wrong, &r_point, &c_w, &cs_keys.user_secret, &kgc.master_secret);
        assert!(!is_match_wrong, "Invalid keyword should NOT produce a match");
    }
}
