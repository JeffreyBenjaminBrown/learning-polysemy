

module Wut where

import Data.ByteString (ByteString)

import Polysemy         (Member, Members, Sem)
import Polysemy.KVStore
import Polysemy.Internal

newtype Username     = Username ByteString
newtype Password     = Password ByteString
newtype PasswordHash = PasswordHash ByteString

-- Our two effects are `KVStore` and `CryptoHash`.

-- Rather than define KVStore, we use one of Polysemy's stock effects:
-- https://hackage.haskell.org/package/polysemy-zoo-0.5.0.1/docs/Polysemy-KVStore.html#v:writeKV

-- | a GADT. `m` is a monad, `a` the return value.
data CryptoHash m a where
  -- | Generates a hash from a password
  MakeHash :: Password -> CryptoHash m PasswordHash
  -- | Check if a password matches a hash
  ValidateHash :: Password -> PasswordHash -> CryptoHash m Bool

-- `CryptoHash` is not monadic, but Polysemy's `Sem r` is,
-- where `r` is a list of effects.
-- So we need to get from one to the other:

makeHash :: Member CryptoHash r -- `CryptoHash` must be in `r`
  => Password -> Sem r PasswordHash
makeHash x =
  send -- Polysemy defines `send`
  (MakeHash x :: CryptoHash (Sem r) PasswordHash)

validateHash :: Member CryptoHash r
  => Password -> PasswordHash -> Sem r Bool
validateHash password hash =
  send (ValidateHash password hash :: CryptoHash (Sem r) Bool)

addUser ::
  Members [CryptoHash, KVStore Username PasswordHash] r
  => Username -> Password -> Sem r ()
addUser username password = do
    hashedPassword <- makeHash password
    writeKV username hashedPassword

validatePassword ::
  Members [CryptoHash, KVStore Username PasswordHash] r
  => Username -> Password -> Sem r Bool
validatePassword username password = do
    hashInStore <- lookupKV username
    case hashInStore of
      Just h  -> validateHash password h
      Nothing -> return False

-- | = Implementation details.
-- (Polysemy calls these "interpretations".)
