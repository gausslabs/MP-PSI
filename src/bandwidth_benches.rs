pub trait BandwidthBench {
    fn get_byte_size(&self) -> usize;
}

impl BandwidthBench for bfv::SecretKeyProto {
    fn get_byte_size(&self) -> usize {
        self.coefficients.len()
    }
}

impl BandwidthBench for bfv::CollectivePublicKeyShareProto {
    fn get_byte_size(&self) -> usize {
        self.clone()
            .share
            .unwrap()
            .coefficients
            .iter()
            .fold(0, |acc, vec| acc + vec.len())
    }
}

impl BandwidthBench for bfv::CollectiveRlkShare1Proto {
    fn get_byte_size(&self) -> usize {
        self.shares.iter().fold(0, |acc, poly| {
            poly.coefficients
                .iter()
                .fold(acc, |acc, vec| acc + vec.len())
        })
    }
}

impl BandwidthBench for bfv::CollectiveRlkShare2Proto {
    fn get_byte_size(&self) -> usize {
        self.shares.iter().fold(0, |acc, poly| {
            acc + poly.coefficients.iter().fold(0, |acc, vec| acc + vec.len())
        })
    }
}

impl BandwidthBench for bfv::CiphertextProto {
    fn get_byte_size(&self) -> usize {
        self.c.iter().fold(0, |acc, poly| {
            acc + poly.coefficients.iter().fold(0, |acc, vec| acc + vec.len())
        })
    }
}

impl BandwidthBench for bfv::CollectiveRlkAggTrimmedShare1Proto {
    fn get_byte_size(&self) -> usize {
        self.shares.iter().fold(0, |acc, poly| {
            acc + poly.coefficients.iter().fold(0, |acc, vec| acc + vec.len())
        })
    }
}

impl BandwidthBench for bfv::CollectiveDecryptionShareProto {
    fn get_byte_size(&self) -> usize {
        self.clone()
            .share
            .unwrap()
            .coefficients
            .iter()
            .fold(0, |acc, vec| acc + vec.len())
    }
}
