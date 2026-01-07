use super::error::AttackError;
use crate::hqc::hqcgf2::HqcGf2;
pub trait Attack {
    fn name(&self) -> &'static str;
    /// output y' has weight w if successful, None otherwise
    fn solve(
        &self,
        n: usize,
        w: usize,
        h: &HqcGf2,
        s: &HqcGf2,
    ) -> Result<Option<HqcGf2>, AttackError>;
}
