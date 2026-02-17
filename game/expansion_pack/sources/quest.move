module expansion_pack::quest;

use game_core::hero::{Self, Hero, HeroMarker};
use monban::monban::{Self, AccessRegistry};

public struct QUEST_COMPLETED has drop {}

public fun complete_quest(hero: &mut Hero, registry: &AccessRegistry<HeroMarker>) {
    // This is the "magic" step. We create a witness for OUR package type (QUEST_COMPLETED).
    // The core game checks if THIS package is whitelisted before allowing the level up.
    let witness = monban::create_witness(QUEST_COMPLETED {});

    // We pass our witness to the core game function.
    hero::level_up(hero, registry, witness);
}
