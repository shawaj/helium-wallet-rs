use crate::{
    cmd::*,
    result::Result,
    traits::{TxnEnvelope, TxnFee, TxnSign},
};
use helium_api::{BlockchainTxnStakeValidatorV1, Hnt, PendingTxnStatus};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
/// Onboard a given encoded validator staking transactiom with this wallet.
/// transaction signed by the Helium staking server.
pub struct Cmd {
    /// Address of the validator to stake
    address: PublicKey,

    /// Amoun to stake
    stake: Hnt,

    /// Whether to commit the transaction to the blockchain
    #[structopt(long)]
    commit: bool,
}

impl Cmd {
    pub fn run(&self, opts: Opts) -> Result {
        let password = get_password(false)?;
        let wallet = load_wallet(opts.files)?;
        let keypair = wallet.decrypt(password.as_bytes())?;

        let client = helium_api::Client::new_with_base_url(api_url(wallet.public_key.network));

        let mut txn = BlockchainTxnStakeValidatorV1 {
            address: self.address.to_vec(),
            owner: wallet.public_key.to_vec(),
            stake: self.stake.to_bones(),
            fee: 0,
            owner_signature: vec![],
        };

        txn.fee = txn.txn_fee(&get_txn_fees(&client)?)?;
        txn.owner_signature = txn.sign(&keypair)?;

        let envelope = txn.in_envelope();
        let status = if self.commit {
            Some(client.submit_txn(&envelope)?)
        } else {
            None
        };
        print_txn(&envelope, &txn, &status, opts.format)
    }
}

fn print_txn(
    envelope: &BlockchainTxn,
    txn: &BlockchainTxnStakeValidatorV1,
    status: &Option<PendingTxnStatus>,
    format: OutputFormat,
) -> Result {
    let validator = PublicKey::from_bytes(&txn.address)?.to_string();
    match format {
        OutputFormat::Table => {
            ptable!(
                ["Key", "Value"],
                ["Validator", validator],
                ["Fee", txn.fee],
                ["Hash", status_str(status)]
            );
            print_footer(status)
        }
        OutputFormat::Json => {
            let table = json!({
                "validator" : validator,
                "fee": txn.fee,
                "txn": envelope.to_b64()?,
                "hash": status_json(status)
            });
            print_json(&table)
        }
    }
}
