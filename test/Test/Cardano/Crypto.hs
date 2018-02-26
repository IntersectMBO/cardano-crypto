{-# LANGUAGE OverloadedStrings #-}

module Test.Cardano.Crypto
    ( tests
    ) where

import Foundation.Check

import qualified Test.Cardano.Crypto.Praos as Praos

tests :: Test
tests = Group "Crypto"
    [ Praos.tests
    ]
