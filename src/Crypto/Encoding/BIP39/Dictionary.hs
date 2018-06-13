{-# LANGUAGE NoImplicitPrelude    #-}
{-# LANGUAGE Rank2Types           #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE KindSignatures       #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE FlexibleInstances    #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE OverloadedStrings    #-}

module Crypto.Encoding.BIP39.Dictionary
    ( -- * Mnemonic Sentence
      MnemonicSentence(..)
    , MnemonicPhrase(..)
    , ValidMnemonicSentence
    , mnemonicPhrase
    , checkMnemonicPhrase
    , mnemonicPhraseToMnemonicSentence
    , mnemonicSentenceToMnemonicPhrase
    , mnemonicSentenceToString
    , mnemonicPhraseToString
    , translateTo
    , -- ** Dictionary
      Dictionary(..)
    , WordIndex
    , wordIndex
    , unWordIndex

    , Elem
    ) where

import           Basement.String (String)
import           Basement.Nat
import           Basement.Sized.List (ListN)
import qualified Basement.Sized.List as ListN
import           Basement.NormalForm
import           Basement.Compat.Typeable
import           Basement.Types.OffsetSize (Offset(..))
import           Basement.From (TryFrom(..))
import           Basement.Imports

import           Data.Maybe (fromMaybe)
import           Data.List (intersperse)

import           Data.Kind (Constraint)

import           GHC.TypeLits
import           GHC.Exts (IsList(..))

-- | this discribe the property of the Dictionary and will alllow to
-- convert from a mnemonic phrase to 'MnemonicSentence'
--
-- This is especially needed to build the BIP39 'Seed'
--
data Dictionary = Dictionary
    { dictionaryIndexToWord :: WordIndex -> String
      -- ^ This function will retrieve the mnemonic word associated to the
      -- given 'WordIndex'.
    , dictionaryWordToIndex :: String -> WordIndex
      -- ^ This function will retrieve the 'WordIndex' from a given mnemonic
      -- word.
    , dictionaryTestWord :: String -> Bool
      -- ^ test a given word is in the dictionary
    , dictionaryWordSeparator :: String
      -- ^ joining string (e.g. space for english)
    }
  deriving (Typeable)

-- | Index of the mnemonic word in the 'Dictionary'
--
-- 'WordIndex' are within range of [0..2047]
--
newtype WordIndex = WordIndex { unWordIndex :: Offset String }
    deriving (Show, Eq, Ord, Typeable, NormalForm)
instance Enum WordIndex where
    toEnum = wordIndex . toEnum
    fromEnum = fromEnum . unWordIndex
    succ (WordIndex (Offset v))
        | v < 2047 = WordIndex (Offset (succ v))
        | otherwise = error "WordIndex out of bound"
    pred (WordIndex (Offset v))
        | v <= 0 = error "WordIndex out of bound"
        | otherwise = WordIndex (Offset (pred v))
instance Bounded WordIndex where
    minBound = WordIndex (Offset 0)
    maxBound = WordIndex (Offset 2047)
instance TryFrom (Offset String) WordIndex where
    tryFrom w
        | w < 2048  = Just (WordIndex w)
        | otherwise = Nothing
instance TryFrom Int WordIndex where
    tryFrom v
        | v >= 0    = tryFrom (Offset v :: Offset String)
        | otherwise = Nothing

wordIndex :: Offset String -> WordIndex
wordIndex w = case tryFrom w of
    Nothing -> error ("Error: word index should be between 0 to 2047. " <> show w)
    Just wi -> wi

-- | Mnemonic Sentence is a list of 'WordIndex'.
--
-- This is the generic representation of a mnemonic phrase that can be used for
-- transalating to a different dictionary (example: English to Japanese).
--
-- This is mainly used to convert from/to the 'Entropy' and for 'cardanoSlSeed'
--
newtype MnemonicSentence (mw :: Nat) = MnemonicSentence
    { mnemonicSentenceToListN :: ListN mw WordIndex
    }
  deriving (Show, Eq, Ord, Typeable, NormalForm)
instance ValidMnemonicSentence mw => IsList (MnemonicSentence mw) where
    type Item (MnemonicSentence mw) = WordIndex
    fromList = MnemonicSentence . fromMaybe (error "invalid mnemonic size") . ListN.toListN
    toList = ListN.unListN . mnemonicSentenceToListN

-- | Type Constraint to validate the given 'Nat' is valid for the supported
-- 'MnemonicSentence'
type ValidMnemonicSentence (mw :: Nat) =
    ( KnownNat mw
    , NatWithinBound Int mw
    , Elem mw '[9, 12, 15, 18, 21, 24]
    )

-- | Human readable representation of a 'MnemonicSentence'
--
newtype MnemonicPhrase (mw :: Nat) = MnemonicPhrase
    { mnemonicPhraseToListN :: ListN mw String
    }
  deriving (Show, Eq, Ord, Typeable, NormalForm)
instance ValidMnemonicSentence mw => IsList (MnemonicPhrase mw) where
    type Item (MnemonicPhrase mw) = String
    fromList = fromMaybe (error "invalid mnemonic phrase") . mnemonicPhrase
    toList = ListN.unListN . mnemonicPhraseToListN

mnemonicPhrase :: forall mw . ValidMnemonicSentence mw => [String] -> Maybe (MnemonicPhrase mw)
mnemonicPhrase l = MnemonicPhrase <$> ListN.toListN l
{-# INLINABLE mnemonicPhrase #-}

-- | check a given 'MnemonicPhrase' is valid for the given 'Dictionary'
--
checkMnemonicPhrase :: forall mw . ValidMnemonicSentence mw
                    => Dictionary
                    -> MnemonicPhrase mw
                    -> Bool
checkMnemonicPhrase dic (MnemonicPhrase ln) =
    ListN.foldl' (\acc s -> (dictionaryTestWord dic s && acc)) True ln

-- | convert the given 'MnemonicPhrase' to a generic 'MnemonicSentence'
-- with the given 'Dictionary'.
--
-- This function assumes the 'Dictionary' and the 'MnemonicPhrase' are
-- compatible (see 'checkMnemonicPhrase').
--
mnemonicPhraseToMnemonicSentence :: forall mw . ValidMnemonicSentence mw
                                 => Dictionary
                                 -> MnemonicPhrase mw
                                 -> MnemonicSentence mw
mnemonicPhraseToMnemonicSentence dic (MnemonicPhrase ln) = MnemonicSentence $
    ListN.map (dictionaryWordToIndex dic) ln

-- | convert the given generic 'MnemonicSentence' to a human readable
-- 'MnemonicPhrase' targetting the language of the given 'Dictionary'.
mnemonicSentenceToMnemonicPhrase :: forall mw . ValidMnemonicSentence mw
                                 => Dictionary
                                 -> MnemonicSentence mw
                                 -> MnemonicPhrase mw
mnemonicSentenceToMnemonicPhrase dic (MnemonicSentence ln) = MnemonicPhrase $
    ListN.map (dictionaryIndexToWord dic) ln

mnemonicPhraseToString :: forall mw . ValidMnemonicSentence mw
                       => Dictionary
                       -> MnemonicPhrase mw
                       -> String
mnemonicPhraseToString dic (MnemonicPhrase ln) = mconcat $
    intersperse (dictionaryWordSeparator dic) (ListN.unListN ln)

mnemonicSentenceToString :: forall mw . ValidMnemonicSentence mw
                         => Dictionary
                         -> MnemonicSentence mw
                         -> String
mnemonicSentenceToString dic = mnemonicPhraseToString dic
                             . mnemonicSentenceToMnemonicPhrase dic

-- | translate the given 'MnemonicPhrase' from one dictionary into another.
--
-- This function assumes the source dictionary is compatible with the given
-- 'MnemonicPhrase' (see 'checkMnemonicPhrase')
--
translateTo :: forall mw . ValidMnemonicSentence mw
            => Dictionary -- ^ source dictionary
            -> Dictionary -- ^ destination dictionary
            -> MnemonicPhrase mw
            -> MnemonicPhrase mw
translateTo dicSrc dicDst (MnemonicPhrase ln) = MnemonicPhrase $
    ListN.map (dictionaryIndexToWord dicDst . dictionaryWordToIndex dicSrc) ln

------------------------------------------------------------------------
-- Helpers
------------------------------------------------------------------------

-- | convenient type level constraint to validate a given 'Nat' e is an elemnt
-- of the list of 'Nat' l.
type family Elem (e :: Nat) (l :: [Nat]) :: Constraint where
    Elem e '[] = TypeError ('Text "offset: field "
             ':<>: 'ShowType e
             ':<>: 'Text " not elements of valids values")
    Elem e (e ': _) = ()
    Elem e (_ ': xs) = Elem e xs
