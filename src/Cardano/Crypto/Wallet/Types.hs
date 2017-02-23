{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Cardano.Crypto.Wallet.Types
    ( ChainCode(..)
    ) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B (pack)
import           Data.ByteArray (ByteArrayAccess, convert)
import qualified Data.ByteArray as B (splitAt, length, append)

newtype ChainCode = ChainCode ByteString
    deriving (Show,Eq,ByteArrayAccess)
