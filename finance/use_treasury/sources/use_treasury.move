module use_treasury::use_treasury;

use monban::monban::{Self, AccessRegistry};
use treasury::treasury::{Self, Treasury, Marker};

public struct W has drop {}

public fun remove_from_treasury(
    treasury: &mut Treasury,
    access_registry: &AccessRegistry<Marker>,
    ctx: &mut TxContext,
) {
    let witness = monban::create_witness(W {});
    let coin = treasury::withdraw_from_treasury(treasury, access_registry, witness, 1, ctx);
    transfer::public_transfer(coin, ctx.sender());
}
