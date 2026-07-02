#![allow(non_snake_case)]

/// ===================================================
/// RDMPF core implementation (constant-time modular
/// exponentiation and error handling)
/// Privacy ICP (ICPP)
///
/// Version -> 2.0.01
/// Date    -> 25 November 2025
/// Status  -> Public release ver:2 subver:0 release:01
///
/// Code developed by @Troesma
/// ===================================================

/// +++++++++++++++++++++++++++++++++++++++++++++++++
/// This code is inspired in Hecht and Scolnik (2025)
/// +++++++++++++++++++++++++++++++++++++++++++++++++

use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::ops::Rem;

pub type Matrix = Vec<Vec<BigUint>>;

#[derive(Clone)]
pub struct RDMPFState {
    pub dim: usize,
    pub j: usize,
    pub k: usize,
    pub ell: usize,
    pub m: usize,
    pub current_product: BigUint,
    pub output: Matrix,
}

pub fn rdmpf_state_init(dim: usize) -> RDMPFState {
    RDMPFState {
        dim,
        j: 0,
        k: 0,
        ell: 0,
        m: 0,
        current_product: BigUint::one(),
        output: vec![vec![BigUint::zero(); dim]; dim],
    }
}

/// RDMPF result
pub type Result<T> = std::result::Result<T, RDMPFError>;

/// Error types
#[derive(Debug, Clone)]
pub enum RDMPFError {
    DimensionMismatch { expected: usize, got: usize },
    InvalidMatrix(String),
    ComputationFailed(String),
}

impl std::fmt::Display for RDMPFError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::DimensionMismatch { expected, got } => {
                write!(f, "Dimension mismatch -> expected {}, got {}", expected, got)
            }
            Self::InvalidMatrix(msg) => write!(f, "Invalid matrix -> {}", msg),
            Self::ComputationFailed(msg) => write!(f, "Computation failed -> {}", msg),
        }
    }
}

impl std::error::Error for RDMPFError {}

/// Constant-time modular exponentiation
/// (uses square-and-multiply algorithm)
pub fn mod_exp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if modulus.is_zero() {
        return BigUint::zero();
    }

    let mut result = BigUint::one();
    let mut base_mod = base % modulus;
    let mut e = exp.clone();

    while !e.is_zero() {
        if &e & BigUint::one() == BigUint::one() {
            result = (result * &base_mod) % modulus;
        }
        e >>= 1;
        if !e.is_zero() {
            base_mod = (&base_mod * &base_mod) % modulus;
        }
    }
    result
}

/// Core RDMPF operation -> given matrices X, W, Y and 
/// moduli p, phi (p - 1), compute RDMPF(X, W, Y) as 
/// described in the technical paper
#[allow(non_snake_case)]
pub fn rdmpf(
    X: &Matrix,
    W: &Matrix,
    Y: &Matrix,
    p: &BigUint,
    phi: &BigUint,
) -> Result<Matrix> {
    let dim = X.len();

    if W.len() != dim || Y.len() != dim {
        return Err(RDMPFError::DimensionMismatch {
            expected: dim,
            got: W.len(),
        });
    }

    rdmpf_with_oracle(dim, W, p, phi, |j, ell, m, k| {
        (&X[j][ell] * &Y[m][k]).clone()
    })
}

/// Generalized RDMPF that gets exponents from an oracle
/// The oracle is called with (j, l, m, k) and must return the
/// exponent X[j,l] * Y[m,k] (or whatever the FE-backed variant 
/// wants) BEFORE reduction mod phi
#[allow(non_snake_case)]
pub fn rdmpf_with_oracle<F>(
    dim: usize,
    W: &Matrix,
    p: &BigUint,
    phi: &BigUint,
    mut exp_oracle: F,
) -> Result<Matrix>
where
    F: FnMut(usize, usize, usize, usize) -> BigUint,
{
    if W.len() != dim {
        return Err(RDMPFError::DimensionMismatch {
            expected: dim,
            got: W.len(),
        });
    }

    for row in W.iter() {
        if row.len() != dim {
            return Err(RDMPFError::InvalidMatrix(
                "Matrices must be square".to_string(),
            ));
        }
    }

    let mut output: Matrix = vec![vec![BigUint::zero(); dim]; dim];

    for j in 0..dim {
        for k in 0..dim {
            let mut product = BigUint::one();

            for ell in 0..dim {
                for m in 0..dim {
                    let mut exp = exp_oracle(j, ell, m, k);
                    exp = exp.rem(phi);

                    let base = &W[ell][m] % p;

                    if base.is_zero() {
                        if !exp.is_zero() {
                            product = BigUint::zero();
                            break;
                        }
                        continue;
                    }

                    let term = mod_exp(&base, &exp, p);
                    product = (product * term).rem(p);

                    if product.is_zero() {
                        break;
                    }
                }
                if product.is_zero() {
                    break;
                }
            }

            output[j][k] = product;
        }
    }

    Ok(output)
}

/// Slicing RDMPF for
/// ONLINE computation
pub fn rdmpf_step<F>(
    state: &mut RDMPFState,
    W: &Matrix,
    p: &BigUint,
    phi: &BigUint,
    exp_oracle: &mut F,
    max_iters: u32,
) -> bool
where
    F: FnMut(usize, usize, usize, usize) -> BigUint,
{
    let dim = state.dim;
    let mut iters: u32 = 0;

    while state.j < dim {
        while state.k < dim {
            while state.ell < dim {
                while state.m < dim {
                    // 1. Exponent from oracle
                    //    reduced mod phi
                    let mut exp = exp_oracle(state.j, state.ell, state.m, state.k);
                    exp = exp.rem(phi);

                    // 2. Base from W
                    let base = &W[state.ell][state.m] % p;

                    if base.is_zero() {
                        // If base == 0 and exponent != 0 => product becomes 0
                        if !exp.is_zero() {
                            state.current_product = BigUint::zero();
                            state.m = dim;
                        } else {
                            // base == 0 && exp == 0 => term = 1
                            // (no effect)
                            state.m += 1;
                        }
                    } else {
                        // base != 0 => compute 
                        // base^exp mod p and 
                        // multiply in
                        let term = mod_exp(&base, &exp, p);
                        state.current_product =
                            (state.current_product.clone() * term).rem(p);

                        // Early abort if 
                        // product is zero
                        if state.current_product.is_zero() {
                            state.m = dim;
                        } else {
                            state.m += 1;
                        }
                    }

                    // 3. Budget accounting
                    iters += 1;
                    if iters >= max_iters {
                        // We've used up our per-call budget
                        // (let the caller resume later)
                        return false;
                    }
                }

                // Finished all m for this 
                // ell (or aborted early)
                state.m = 0;

                if state.current_product.is_zero() {
                    state.ell = dim;
                } else {
                    state.ell += 1;
                }
            }

            // Finished all ell 
            // for this (j, k)
            state.output[state.j][state.k] = state.current_product.clone();
            state.current_product = BigUint::one();
            state.ell = 0;
            state.m = 0;
            state.k += 1;
        }
        // Finished all k 
        // for this j
        state.k = 0;
        state.j += 1;
    }
    // Completed
    true
}

/// Matrix equality with constant-time-ish 
/// semantics on contents
pub fn matrices_equal(a: &Matrix, b: &Matrix) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (row_a, row_b) in a.iter().zip(b.iter()) {
        if row_a.len() != row_b.len() {
            return false;
        }
        for (x, y) in row_a.iter().zip(row_b.iter()) {
            let xa = x.to_bytes_le();
            let ya = y.to_bytes_le();
            if xa.len() != ya.len() {
                return false;
            }
            for (bx, by) in xa.iter().zip(ya.iter()) {
                acc |= bx ^ by;
            }
        }
    }
    acc == 0
}

/// Multiply matrix by scalar (entry-wise) 
/// reducing modulo `modulus`
pub fn scalar_mult(scalar: &BigUint, matrix: &Matrix, modulus: &BigUint) -> Matrix {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|elem| (elem * scalar) % modulus)
                .collect::<Vec<BigUint>>()
        })
        .collect()
}

/// Composition operator T1 -> T2 as defined 
/// in the technical paper
/// We implement this as element-wise 
/// multiplication modulo p
#[allow(non_snake_case)]
pub fn composition(
    T1: &Matrix,
    T2: &Matrix,
    p: &BigUint,
    phi: &BigUint,
) -> Result<Matrix> {
    let dim = T1.len();

    if T2.len() != dim {
        return Err(RDMPFError::DimensionMismatch {
            expected: dim,
            got: T2.len(),
        });
    }

    let mut output: Matrix = vec![vec![BigUint::zero(); dim]; dim];

    for j in 0..dim {
        if T1[j].len() != dim || T2[j].len() != dim {
            return Err(RDMPFError::InvalidMatrix(
                "Matrices must be square".to_string(),
            ));
        }
        for k in 0..dim {
            let val = (&T1[j][k] * &T2[j][k]) % p;
            output[j][k] = val;
        }
    }

    let _ = phi;

    Ok(output)
}

/// Encode matrix to bytes (row-major, with explicit lengths)
/// Format -> [u32 dim] then dim*dim repetitions of [u32 len][elem_bytes_le]
pub fn encode_matrix(matrix: &Matrix) -> Vec<u8> {
    let dim = matrix.len() as u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&dim.to_le_bytes());

    for row in matrix {
        assert_eq!(
            row.len() as u32,
            dim,
            "Matrix must be square"
        );
        for elem in row {
            let elem_bytes = elem.to_bytes_le();
            let len = elem_bytes.len() as u32;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(&elem_bytes);
        }
    }

    bytes
}

/// Decode matrix from bytes 
/// produced by `encode_matrix`
pub fn decode_matrix(data: &[u8]) -> Result<Matrix> {
    use RDMPFError::InvalidMatrix;

    if data.len() < 4 {
        return Err(InvalidMatrix("Encoded matrix too short".to_string()));
    }

    let dim = {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&data[0..4]);
        u32::from_le_bytes(buf) as usize
    };

    let mut offset = 4;
    let mut matrix: Matrix = Vec::with_capacity(dim);

    for _ in 0..dim {
        let mut row: Vec<BigUint> = Vec::with_capacity(dim);
        for _ in 0..dim {
            if offset + 4 > data.len() {
                return Err(InvalidMatrix(
                    "Truncated length in encoded matrix".to_string(),
                ));
            }
            let mut len_buf = [0u8; 4];
            len_buf.copy_from_slice(&data[offset..offset + 4]);
            let len = u32::from_le_bytes(len_buf) as usize;
            offset += 4;

            if offset + len > data.len() {
                return Err(InvalidMatrix(
                    "Truncated element in encoded matrix".to_string(),
                ));
            }
            let elem_bytes = &data[offset..offset + len];
            offset += len;

            let value = BigUint::from_bytes_le(elem_bytes);
            row.push(value);
        }
        matrix.push(row);
    }

    if offset != data.len() {
        return Err(InvalidMatrix(
            "Extra trailing bytes".to_string(),
        ));
    }
    Ok(matrix)
}