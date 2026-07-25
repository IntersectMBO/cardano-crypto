{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE FlexibleInstances #-}

-- | 'AsBytes' grants 'ByteArrayAccess' to @basement@\/@foundation@ byte-array
-- types ('Base.String', 'Base.UArray') without defining orphan instances on
-- those types directly.
--
-- The @ram@ package (a maintained fork of the now-unmaintained @memory@
-- package, which used to provide these instances behind its @foundation@
-- cabal flag) does not ship them. We can't define them as ordinary orphan
-- instances on 'Base.String' \/ 'Base.UArray' because the pinned @inspector@
-- test dependency already defines the same orphans for its own internal use
-- (it also converts between Foundation byte-array types and 'ram'-based
-- 'ByteArrayAccess'). Two packages both defining an orphan instance for the
-- same type conflict wherever both packages are visible together, as they
-- are in the golden-test executables, which depend on both this library and
-- @inspector@. Instances on the local 'AsBytes' wrapper can't collide with
-- anything defined elsewhere, since nothing outside this package mentions
-- 'AsBytes'.
module Compat.ByteArray
    ( AsBytes (..)
    ) where

import Data.ByteArray (ByteArrayAccess (..))
import Data.Word      (Word8)
import Foreign.Ptr    (castPtr)

import qualified Basement.String           as Base (Encoding (UTF8), String, toBytes)
import qualified Basement.Types.OffsetSize as Base
import qualified Basement.UArray           as Base

import Prelude hiding (length)

-- | Wrapper granting 'ByteArrayAccess' to a foundation\/basement byte-array
-- type without creating an orphan instance on the bare type itself.
newtype AsBytes a = AsBytes a

baseUarrayRecastW8 :: Base.PrimType ty => Base.UArray ty -> Base.UArray Word8
baseUarrayRecastW8 = Base.recast

instance Base.PrimType ty => ByteArrayAccess (AsBytes (Base.UArray ty)) where
    length (AsBytes a) = let Base.CountOf i = Base.length (baseUarrayRecastW8 a) in i
    withByteArray (AsBytes a) f = Base.withPtr (baseUarrayRecastW8 a) (f . castPtr)

instance ByteArrayAccess (AsBytes Base.String) where
    length (AsBytes str) = let Base.CountOf i = Base.length bytes in i
      where
        -- Foundation's length returns a number of elements, not bytes.
        bytes = Base.toBytes Base.UTF8 str
    withByteArray (AsBytes str) f = withByteArray (AsBytes (Base.toBytes Base.UTF8 str)) f
