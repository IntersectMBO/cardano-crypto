-- |
-- Module      : Cardano.Crypto.Wallet.Encrypted
-- Description : Versioned encrypted root-key envelopes.
--
-- New writes use a @v2@ CBOR envelope with random salt, random nonce,
-- Argon2id-derived wrapping keys, and XChaCha20-Poly1305 authentication.
-- Legacy @v1@ keys remain readable for compatibility and migration only.
module Cardano.Crypto.Wallet.Encrypted
    ( EncryptedKey
    , XPrvFormat(..)
    , XPrvError(..)
    , encryptedKey
    , encryptedKeyFormat
    , unEncryptedKey
    , Signature(..)
    , encryptedCreate
    , encryptedCreateDirectWithTweak
    , encryptedValidatePassphrase
    , encryptedUpgradeToV2
    , encryptedRewrapToV2
    , encryptedChangePass
    , encryptedSign
    , encryptedPublic
    , encryptedChainCode
    , encryptedDerivePrivate
    , encryptedDerivePublic
    , withFastKdfForTesting
    , withDeterministicRandomnessForTesting
    ) where

import           Control.DeepSeq
import           Control.Exception               (bracket)
import           Data.Bits                       (shiftR)
import           Data.ByteArray                  (ByteArrayAccess, ScrubbedBytes,
                                                  convert, withByteArray)
import qualified Data.ByteArray                  as B
import           Data.ByteString                 (ByteString)
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Lazy            as BL
import           Data.IORef                      (IORef, newIORef, readIORef,
                                                  writeIORef)
import           Data.Word
import           Foreign.C.Types
import           Foreign.Ptr
import           System.IO.Unsafe                (unsafePerformIO)

import           Codec.CBOR.Decoding             (Decoder, decodeBytes,
                                                  decodeListLenOf, decodeWord)
import           Codec.CBOR.Encoding             (encodeBytes,
                                                  encodeListLen, encodeWord)
import qualified Codec.CBOR.Read                 as CBOR
import qualified Codec.CBOR.Write                as CBOR

import           Cardano.Crypto.Wallet.Types     (DerivationIndex,
                                                  DerivationScheme (..))

legacyKeySize, publicKeySize, ccSize, signatureSize :: Int
legacyKeySize = 64
publicKeySize = 32
ccSize = 32
signatureSize = 64

type PublicKey = ByteString
type ChainCode = ByteString
type Salt = ByteString
type Nonce = ByteString
type Ciphertext = ByteString
type AuthenticationTag = ByteString
type AadContext = ByteString
type SecretKey = ScrubbedBytes

legacyTotalKeySize :: Int
legacyTotalKeySize = legacyKeySize + publicKeySize + ccSize

v2Version, argon2idId, xchacha20poly1305Id :: Word
v2Version = 2
argon2idId = 1
xchacha20poly1305Id = 1

data KdfParams = KdfParams
    { kdfMemoryKiB   :: !Word
    , kdfTimeCost    :: !Word
    , kdfParallelism :: !Word
    , kdfOutputLength :: !Word
    }

productionKdfParams, fastTestKdfParams :: KdfParams
productionKdfParams = KdfParams 131072 3 4 32
fastTestKdfParams = KdfParams 4096 1 1 32

runtimeKdfParamsRef :: IORef KdfParams
runtimeKdfParamsRef = unsafePerformIO (newIORef productionKdfParams)
{-# NOINLINE runtimeKdfParamsRef #-}

data RandomMode = SystemRandom | DeterministicRandom !Word64

randomModeRef :: IORef RandomMode
randomModeRef = unsafePerformIO (newIORef SystemRandom)
{-# NOINLINE randomModeRef #-}

readRuntimeKdfParams :: IO KdfParams
readRuntimeKdfParams = readIORef runtimeKdfParamsRef

-- | Test-only helper to reduce Argon2id runtime cost while keeping the v2
-- envelope metadata fixed to the production policy.
withFastKdfForTesting :: IO a -> IO a
withFastKdfForTesting = bracket install restore . const
  where
    install = do
        original <- readIORef runtimeKdfParamsRef
        writeIORef runtimeKdfParamsRef fastTestKdfParams
        pure original
    restore original = writeIORef runtimeKdfParamsRef original

withDeterministicRandomnessForTesting :: IO a -> IO a
withDeterministicRandomnessForTesting = bracket install restore . const
  where
    install = do
        original <- readIORef randomModeRef
        writeIORef randomModeRef (DeterministicRandom 0)
        pure original
    restore original = writeIORef randomModeRef original

productionArgonMemoryKiB, productionArgonTimeCost, productionArgonParallelism, productionArgonOutputLength :: Word
productionArgonMemoryKiB = kdfMemoryKiB productionKdfParams
productionArgonTimeCost = kdfTimeCost productionKdfParams
productionArgonParallelism = kdfParallelism productionKdfParams
productionArgonOutputLength = kdfOutputLength productionKdfParams

saltSize, nonceSize, tagSize :: Int
saltSize = 32
nonceSize = 24
tagSize = 16

newtype Signature = Signature ByteString
    deriving (NFData)

data XPrvFormat = LegacyV1 | EnvelopeV2
    deriving (Eq, Show)

data XPrvError
    = XPrvDecodeError
    | XPrvUnsupportedVersion
    | XPrvUnsupportedKdf
    | XPrvUnsupportedCipher
    | XPrvInvalidKdfParams
    | XPrvInvalidSaltLength
    | XPrvInvalidNonceLength
    | XPrvInvalidTagLength
    | XPrvInvalidCiphertextLength
    | XPrvAuthenticationFailed
    | XPrvInvalidSecretKey
    | XPrvInvalidPublicKey
    | XPrvInvalidChainCode
    | XPrvPublicKeyMismatch
    | XPrvInternalError
    deriving (Eq, Show)

newtype EncryptedKey = EncryptedKey ByteString
    deriving (NFData, ByteArrayAccess)

data V2Envelope = V2Envelope
    { v2Salt       :: !Salt
    , v2Nonce      :: !Nonce
    , v2PublicKey  :: !PublicKey
    , v2ChainCode  :: !ChainCode
    , v2Ciphertext :: !Ciphertext
    , v2Tag        :: !AuthenticationTag
    } deriving (Eq, Show)

data KeyMaterial = KeyMaterial
    { kmSecretKey :: !SecretKey
    , kmPublicKey :: !PublicKey
    , kmChainCode :: !ChainCode
    }

data PassPhrase

-- map to the C enum : derivation_scheme_mode
type CDerivationScheme = CInt

encryptedKey :: ByteString -> Either XPrvError EncryptedKey
encryptedKey bs = EncryptedKey bs <$ validateSerializedKey bs

encryptedKeyFormat :: EncryptedKey -> XPrvFormat
encryptedKeyFormat (EncryptedKey bs)
    | BS.length bs == legacyTotalKeySize = LegacyV1
    | otherwise = EnvelopeV2

unEncryptedKey :: EncryptedKey -> ByteString
unEncryptedKey (EncryptedKey e) = e

encryptedCreate :: (ByteArrayAccess passphrase, ByteArrayAccess secret, ByteArrayAccess cc)
                => secret
                -> passphrase
                -> cc
                -> Either XPrvError EncryptedKey
encryptedCreate sec pass cc
    | B.length sec /= 32 = Left XPrvInvalidSecretKey
    | B.length cc /= ccSize = Left XPrvInvalidChainCode
    | otherwise = do
        material <- legacyMaterialFromSecret sec cc
        wrapKeyMaterial pass material
{-# NOINLINE encryptedCreate #-}

encryptedCreateDirectWithTweak :: (ByteArrayAccess passphrase, ByteArrayAccess secret)
                               => secret
                               -> passphrase
                               -> Either XPrvError EncryptedKey
encryptedCreateDirectWithTweak sec pass
    | B.length sec /= 96 = Left XPrvInvalidSecretKey
    | otherwise = do
        material <- legacyMaterialFromMasterKey sec
        wrapKeyMaterial pass material
{-# NOINLINE encryptedCreateDirectWithTweak #-}

encryptedValidatePassphrase :: ByteArrayAccess passphrase => EncryptedKey -> passphrase -> Either XPrvError ()
encryptedValidatePassphrase ekey pass = do
    _ <- decryptKeyMaterial ekey pass
    pure ()

encryptedUpgradeToV2 :: ByteArrayAccess passphrase => passphrase -> EncryptedKey -> Either XPrvError EncryptedKey
encryptedUpgradeToV2 = encryptedRewrapToV2

encryptedRewrapToV2 :: ByteArrayAccess passphrase => passphrase -> EncryptedKey -> Either XPrvError EncryptedKey
encryptedRewrapToV2 pass ekey = decryptKeyMaterial ekey pass >>= wrapKeyMaterial pass

encryptedChangePass :: (ByteArrayAccess oldPassPhrase, ByteArrayAccess newPassPhrase)
                    => oldPassPhrase
                    -> newPassPhrase
                    -> EncryptedKey
                    -> Either XPrvError EncryptedKey
encryptedChangePass oldPass newPass ekey = decryptKeyMaterial ekey oldPass >>= wrapKeyMaterial newPass

encryptedSign :: (ByteArrayAccess passphrase, ByteArrayAccess msg)
              => EncryptedKey
              -> passphrase
              -> msg
              -> Either XPrvError Signature
encryptedSign ekey pass msg = do
    material <- decryptKeyMaterial ekey pass
    legacy <- legacyClearBytes material
    -- We keep the legacy signing implementation once the root key has been
    -- authenticated and unwrapped into plaintext key material.
    let (_, sig) = unsafePerformIO ((B.allocRet signatureSize $ \out ->
            withByteArray legacy      $ \k ->
            withByteArray emptySecret $ \p ->
            withByteArray msg         $ \m ->
                wallet_encrypted_sign k p 0 m (fromIntegral $ B.length msg) out) :: IO ((), ByteString))
    Right $ Signature sig

encryptedDerivePrivate :: ByteArrayAccess passphrase
                       => DerivationScheme
                       -> EncryptedKey
                       -> passphrase
                       -> DerivationIndex
                       -> Either XPrvError EncryptedKey
encryptedDerivePrivate dscheme ekey pass childIndex = do
    material <- decryptKeyMaterial ekey pass
    legacy <- legacyClearBytes material
    -- Child-key derivation semantics stay unchanged; only the wrapping format
    -- differs between legacy v1 and authenticated v2 envelopes.
    child <- legacyDerivePrivate dscheme legacy childIndex
    wrapKeyMaterial pass child

encryptedDerivePublic :: DerivationScheme
                      -> (PublicKey, ChainCode)
                      -> DerivationIndex
                      -> (PublicKey, ChainCode)
encryptedDerivePublic dscheme (pub, cc) childIndex
    | childIndex >= 0x80000000 = error "cannot derive hardened in derive public"
    | otherwise                = unsafePerformIO $ do
        (newCC, newPub) <-
                B.allocRet publicKeySize $ \outPub ->
                B.alloc ccSize           $ \outCc  ->
                withByteArray pub        $ \ppub   ->
                withByteArray cc         $ \pcc    -> do
                    r <- wallet_encrypted_derive_public ppub pcc childIndex outPub outCc (dschemeToC dscheme)
                    if r /= 0 then error "encrypted derive public assumption about index failed" else pure ()
        pure (newPub, newCC)

encryptedPublic :: EncryptedKey -> ByteString
encryptedPublic (EncryptedKey ekey) =
    case encryptedKeyFormat (EncryptedKey ekey) of
        LegacyV1    -> sub legacyKeySize publicKeySize ekey
        EnvelopeV2  -> either (const badEnvelope) v2PublicKey (decodeV2Envelope ekey)
  where
    badEnvelope = error "invalid encrypted key envelope"

encryptedChainCode :: EncryptedKey -> ByteString
encryptedChainCode (EncryptedKey ekey) =
    case encryptedKeyFormat (EncryptedKey ekey) of
        LegacyV1    -> sub (legacyKeySize + publicKeySize) ccSize ekey
        EnvelopeV2  -> either (const badEnvelope) v2ChainCode (decodeV2Envelope ekey)
  where
    badEnvelope = error "invalid encrypted key envelope"

validateSerializedKey :: ByteString -> Either XPrvError ()
validateSerializedKey bs
    | BS.length bs == legacyTotalKeySize = Right ()
    | otherwise = decodeV2Envelope bs >> pure ()

decodeV2Envelope :: ByteString -> Either XPrvError V2Envelope
decodeV2Envelope bs = do
    (rest, envelope) <- either (const $ Left XPrvDecodeError) Right $ CBOR.deserialiseFromBytes decodeEnvelope (BL.fromStrict bs)
    if BL.null rest then pure envelope else Left XPrvDecodeError
    

decodeEnvelope :: Decoder s V2Envelope
decodeEnvelope = do
    decodeListLenOf 9
    version <- decodeWord
    if version /= v2Version then failDecoder XPrvUnsupportedVersion else pure ()
    kdfId <- decodeWord
    if kdfId /= argon2idId then failDecoder XPrvUnsupportedKdf else pure ()
    decodeListLenOf 4
    memoryKiB <- decodeWord
    timeCost <- decodeWord
    parallelism <- decodeWord
    outputLength <- decodeWord
    if (memoryKiB, timeCost, parallelism, outputLength) /= (productionArgonMemoryKiB, productionArgonTimeCost, productionArgonParallelism, productionArgonOutputLength)
        then failDecoder XPrvInvalidKdfParams else pure ()
    salt <- decodeBytes
    if BS.length salt /= saltSize then failDecoder XPrvInvalidSaltLength else pure ()
    cipherId <- decodeWord
    if cipherId /= xchacha20poly1305Id then failDecoder XPrvUnsupportedCipher else pure ()
    nonce <- decodeBytes
    if BS.length nonce /= nonceSize then failDecoder XPrvInvalidNonceLength else pure ()
    aad <- decodeBytes
    ciphertext <- decodeBytes
    if BS.length ciphertext /= legacyKeySize then failDecoder XPrvInvalidCiphertextLength else pure ()
    tag <- decodeBytes
    if BS.length tag /= tagSize then failDecoder XPrvInvalidTagLength else pure ()
    (pub, cc) <- either failDecoder pure $ decodeAad aad
    pure $ V2Envelope
        { v2Salt = salt
        , v2Nonce = nonce
        , v2PublicKey = pub
        , v2ChainCode = cc
        , v2Ciphertext = ciphertext
        , v2Tag = tag
        }

encodeV2Envelope :: V2Envelope -> ByteString
-- | Strict CBOR array encoding with fixed field order for the v2 envelope.
encodeV2Envelope envelope = CBOR.toStrictByteString $ mconcat
    [ encodeListLen 9
    , encodeWord v2Version
    , encodeWord argon2idId
    , encodeListLen 4
    , encodeWord productionArgonMemoryKiB
    , encodeWord productionArgonTimeCost
    , encodeWord productionArgonParallelism
    , encodeWord productionArgonOutputLength
    , encodeBytes (v2Salt envelope)
    , encodeWord xchacha20poly1305Id
    , encodeBytes (v2Nonce envelope)
    , encodeBytes (encodeAad (v2PublicKey envelope) (v2ChainCode envelope))
    , encodeBytes (v2Ciphertext envelope)
    , encodeBytes (v2Tag envelope)
    ]

encodeAad :: PublicKey -> ChainCode -> AadContext
encodeAad pub cc = CBOR.toStrictByteString $ mconcat
    [ encodeListLen 8
    , encodeWord v2Version
    , encodeWord argon2idId
    , encodeListLen 4
    , encodeWord productionArgonMemoryKiB
    , encodeWord productionArgonTimeCost
    , encodeWord productionArgonParallelism
    , encodeWord productionArgonOutputLength
    , encodeWord xchacha20poly1305Id
    , encodeWord 1
    , encodeWord (fromIntegral legacyKeySize)
    , encodeBytes pub
    , encodeBytes cc
    ]

decodeAad :: AadContext -> Either XPrvError (PublicKey, ChainCode)
decodeAad bs =
    case CBOR.deserialiseFromBytes decodeAadFields (BL.fromStrict bs) of
        Left _ -> Left XPrvDecodeError
        Right (rest, result)
            | BL.null rest -> Right result
            | otherwise    -> Left XPrvDecodeError

decodeAadFields :: Decoder s (PublicKey, ChainCode)
decodeAadFields = do
    decodeListLenOf 8
    version <- decodeWord
    if version /= v2Version then failDecoder XPrvUnsupportedVersion else pure ()
    kdfId <- decodeWord
    if kdfId /= argon2idId then failDecoder XPrvUnsupportedKdf else pure ()
    decodeListLenOf 4
    memoryKiB <- decodeWord
    timeCost <- decodeWord
    parallelism <- decodeWord
    outputLength <- decodeWord
    if (memoryKiB, timeCost, parallelism, outputLength) /= (productionArgonMemoryKiB, productionArgonTimeCost, productionArgonParallelism, productionArgonOutputLength)
        then failDecoder XPrvInvalidKdfParams else pure ()
    cipherId <- decodeWord
    if cipherId /= xchacha20poly1305Id then failDecoder XPrvUnsupportedCipher else pure ()
    payloadKind <- decodeWord
    if payloadKind /= 1 then failDecoder XPrvDecodeError else pure ()
    payloadLen <- decodeWord
    if payloadLen /= fromIntegral legacyKeySize then failDecoder XPrvInvalidCiphertextLength else pure ()
    pub <- decodeBytes
    cc <- decodeBytes
    if BS.length pub /= publicKeySize then failDecoder XPrvInvalidPublicKey else pure ()
    if BS.length cc /= ccSize then failDecoder XPrvInvalidChainCode else pure ()
    pure (pub, cc)

decryptKeyMaterial :: ByteArrayAccess passphrase => EncryptedKey -> passphrase -> Either XPrvError KeyMaterial
decryptKeyMaterial ekey pass =
    case encryptedKeyFormat ekey of
        LegacyV1   -> legacyDecrypt ekey pass
        EnvelopeV2 -> v2Decrypt ekey pass

legacyDecrypt :: ByteArrayAccess passphrase => EncryptedKey -> passphrase -> Either XPrvError KeyMaterial
legacyDecrypt (EncryptedKey bs) pass = do
    clear <- cDecrypt bs pass
    keyMaterialFromLegacyBytes clear

v2Decrypt :: ByteArrayAccess passphrase => EncryptedKey -> passphrase -> Either XPrvError KeyMaterial
v2Decrypt (EncryptedKey bs) pass = do
    envelope <- decodeV2Envelope bs
    key <- deriveWrappingKey pass (v2Salt envelope)
    let aad = encodeAad (v2PublicKey envelope) (v2ChainCode envelope)
        ciphertext = v2Ciphertext envelope
        tag = v2Tag envelope
        nonce = v2Nonce envelope
        (status, plaintext) = unsafePerformIO $
            B.allocRet legacyKeySize $ \out ->
                withByteArray ciphertext $ \ct ->
                withByteArray tag        $ \tg ->
                withByteArray aad        $ \ad ->
                withByteArray nonce      $ \np ->
                withByteArray key        $ \kp ->
                    wallet_sodium_xchacha20poly1305_decrypt out ct (fromIntegral $ BS.length ciphertext) tg ad (fromIntegral $ BS.length aad) np kp
    if status /= 0 then Left XPrvAuthenticationFailed else pure ()
    -- Only use the plaintext root key after AEAD authentication and envelope
    -- metadata validation have both succeeded.
    let material = KeyMaterial plaintext (v2PublicKey envelope) (v2ChainCode envelope)
    validateKeyMaterial material
    pure material

wrapKeyMaterial :: ByteArrayAccess passphrase => passphrase -> KeyMaterial -> Either XPrvError EncryptedKey
wrapKeyMaterial pass material = do
    validateKeyMaterial material
    let result = unsafePerformIO $ do
            saltResult <- randomBytesIO saltSize
            nonceResult <- randomBytesIO nonceSize
            pure $ do
                salt <- saltResult
                nonce <- nonceResult
                key' <- deriveWrappingKey pass salt
                -- Public key and chain code stay outside the ciphertext so they
                -- remain accessible, but we bind them cryptographically via AAD.
                let aad = encodeAad (kmPublicKey material) (kmChainCode material)
                    ((status, tag), ciphertext) = unsafePerformIO $
                        B.allocRet legacyKeySize $ \outCipher ->
                            B.allocRet tagSize   $ \outTag    ->
                                withByteArray (kmSecretKey material) $ \plain ->
                                withByteArray aad                  $ \ad    ->
                                withByteArray nonce                $ \np    ->
                                withByteArray key'                 $ \kp    ->
                                    wallet_sodium_xchacha20poly1305_encrypt outCipher outTag plain (fromIntegral legacyKeySize) ad (fromIntegral $ BS.length aad) np kp
                if status /= 0 then Left XPrvInternalError
                else Right $ EncryptedKey $ encodeV2Envelope $ V2Envelope salt nonce (kmPublicKey material) (kmChainCode material) ciphertext tag
    result
{-# NOINLINE wrapKeyMaterial #-}

validateKeyMaterial :: KeyMaterial -> Either XPrvError ()
validateKeyMaterial material = do
    legacy <- legacyClearBytes material
    _ <- cDecrypt (convert legacy) emptySecret
    pure ()

legacyClearBytes :: KeyMaterial -> Either XPrvError ScrubbedBytes
legacyClearBytes material
    | B.length (kmSecretKey material) /= legacyKeySize = Left XPrvInvalidSecretKey
    | BS.length (kmPublicKey material) /= publicKeySize = Left XPrvInvalidPublicKey
    | BS.length (kmChainCode material) /= ccSize = Left XPrvInvalidChainCode
    | otherwise = Right $
        kmSecretKey material
        `B.append` (convert (kmPublicKey material) :: ScrubbedBytes)
        `B.append` (convert (kmChainCode material) :: ScrubbedBytes)

keyMaterialFromLegacyBytes :: ByteArrayAccess ba => ba -> Either XPrvError KeyMaterial
keyMaterialFromLegacyBytes bs
    | B.length bs /= legacyTotalKeySize = Left XPrvDecodeError
    | otherwise =
        let full = convert bs :: ByteString
            secret = convert $ BS.take legacyKeySize full
            pub = BS.take publicKeySize $ BS.drop legacyKeySize full
            cc = BS.drop (legacyKeySize + publicKeySize) full
         in Right $ KeyMaterial secret pub cc

legacyMaterialFromSecret :: (ByteArrayAccess secret, ByteArrayAccess cc) => secret -> cc -> Either XPrvError KeyMaterial
legacyMaterialFromSecret sec cc =
    case (unsafePerformIO $ do
        result <- B.allocRet legacyTotalKeySize $ \ekey ->
            withByteArray emptySecret $ \ppass ->
            withByteArray sec         $ \psec  ->
            withByteArray cc          $ \pcc   ->
                wallet_encrypted_from_secret ppass 0 psec pcc ekey
        pure result) :: (CInt, ByteString)
    of
        (0, raw) -> keyMaterialFromLegacyBytes raw
        _        -> Left XPrvInvalidSecretKey

legacyMaterialFromMasterKey :: ByteArrayAccess secret => secret -> Either XPrvError KeyMaterial
legacyMaterialFromMasterKey sec =
    case (unsafePerformIO $ do
        result <- B.allocRet legacyTotalKeySize $ \ekey ->
            withByteArray emptySecret $ \ppass ->
            withByteArray sec         $ \psec  ->
                wallet_encrypted_new_from_mkg ppass 0 psec ekey
        pure result) :: (CInt, ByteString)
    of
        (0, raw) -> keyMaterialFromLegacyBytes raw
        _        -> Left XPrvInvalidSecretKey

legacyDerivePrivate :: ByteArrayAccess ba => DerivationScheme -> ba -> DerivationIndex -> Either XPrvError KeyMaterial
legacyDerivePrivate dscheme parent childIndex =
    keyMaterialFromLegacyBytes raw
  where
    (_, raw) = unsafePerformIO ((B.allocRet legacyTotalKeySize $ \ekey ->
        withByteArray parent      $ \pparent ->
        withByteArray emptySecret $ \ppass   ->
            wallet_encrypted_derive_private pparent ppass 0 childIndex ekey (dschemeToC dscheme)) :: IO ((), ByteString))

deriveWrappingKey :: ByteArrayAccess passphrase => passphrase -> ByteString -> Either XPrvError ScrubbedBytes
deriveWrappingKey pass salt
    | BS.length salt /= saltSize = Left XPrvInvalidSaltLength
    | otherwise =
        let params = unsafePerformIO readRuntimeKdfParams
            outputLen = fromIntegral (kdfOutputLength params)
            memBytes = fromIntegral (kdfMemoryKiB params) * 1024 :: Word64
            (status, key) = unsafePerformIO $
                B.allocRet outputLen $ \out ->
                    withByteArray pass $ \ppass ->
                    withByteArray salt $ \psalt ->
                        wallet_sodium_argon2id out (fromIntegral outputLen) ppass (fromIntegral $ B.length pass) psalt (fromIntegral $ kdfTimeCost params) memBytes
         in if status == 0 then Right key else Left XPrvInternalError

randomBytesIO :: Int -> IO (Either XPrvError ByteString)
randomBytesIO len = do
    mode <- readIORef randomModeRef
    case mode of
        SystemRandom -> do
            (status, bytes) <- B.allocRet len $ \out -> wallet_sodium_randombytes out (fromIntegral len)
            pure $ if status == 0 then Right bytes else Left XPrvInternalError
        DeterministicRandom counter -> do
            let bytes = deterministicBytes len counter
            writeIORef randomModeRef (DeterministicRandom (counter + 1))
            pure (Right bytes)

deterministicBytes :: Int -> Word64 -> ByteString
deterministicBytes len counter = BS.pack $ take len $ cycle
    [ fromIntegral counter
    , fromIntegral (counter `shiftR` 8)
    , fromIntegral (counter `shiftR` 16)
    , fromIntegral (counter `shiftR` 24)
    , fromIntegral (counter `shiftR` 32)
    , fromIntegral (counter `shiftR` 40)
    , fromIntegral (counter `shiftR` 48)
    , fromIntegral (counter `shiftR` 56)
    ]

cDecrypt :: ByteArrayAccess passphrase => ByteString -> passphrase -> Either XPrvError ScrubbedBytes
cDecrypt bs pass =
    let (status, clear) = unsafePerformIO $
            B.allocRet legacyTotalKeySize $ \out ->
                withByteArray bs   $ \pin  ->
                withByteArray pass $ \ppass ->
                    wallet_encrypted_decrypt pin ppass (fromIntegral $ B.length pass) out
     in if status == 0 then Right clear else Left XPrvAuthenticationFailed

sub :: B.ByteArray c => Int -> Int -> c -> c
sub ofs sz = B.take sz . B.drop ofs

-- | Legacy helpers treat an empty passphrase as the compatibility mode for
-- unencrypted in-memory operations.
emptySecret :: ByteString
emptySecret = BS.empty

dschemeToC :: DerivationScheme -> CDerivationScheme
dschemeToC DerivationScheme1 = 1
dschemeToC DerivationScheme2 = 2

failDecoder :: XPrvError -> Decoder s a
failDecoder = fail . show

-- return 0 if success, otherwise 1 if structure of seed not proper
foreign import ccall "wallet_encrypted_from_secret"
    wallet_encrypted_from_secret :: Ptr PassPhrase -> Word32
                                 -> Ptr Word8        -- 32 bytes seed secret key (non-extended)
                                 -> Ptr Word8        -- 32 bytes chain code
                                 -> Ptr EncryptedKey -- serialized legacy layout buffer
                                 -> IO CInt

foreign import ccall "wallet_encrypted_new_from_mkg"
    wallet_encrypted_new_from_mkg :: Ptr PassPhrase -> Word32
                                  -> Ptr Word8        -- 96 bytes master key generation output
                                  -> Ptr EncryptedKey -- serialized legacy layout buffer
                                  -> IO CInt

foreign import ccall "wallet_encrypted_decrypt"
    wallet_encrypted_decrypt :: Ptr EncryptedKey
                             -> Ptr PassPhrase
                             -> Word32
                             -> Ptr EncryptedKey
                             -> IO CInt

foreign import ccall "wallet_encrypted_sign"
    wallet_encrypted_sign :: Ptr EncryptedKey
                          -> Ptr PassPhrase -> Word32
                          -> Ptr Word8 -> Word32
                          -> Ptr Signature
                          -> IO ()

foreign import ccall "wallet_encrypted_derive_private"
    wallet_encrypted_derive_private :: Ptr EncryptedKey
                                    -> Ptr PassPhrase -> Word32
                                    -> DerivationIndex
                                    -> Ptr EncryptedKey
                                    -> CDerivationScheme
                                    -> IO ()

foreign import ccall "wallet_encrypted_derive_public"
    wallet_encrypted_derive_public :: Ptr PublicKey
                                   -> Ptr ChainCode
                                   -> DerivationIndex
                                   -> Ptr PublicKey
                                   -> Ptr ChainCode
                                   -> CDerivationScheme
                                   -> IO CInt

foreign import ccall "wallet_sodium_randombytes"
    wallet_sodium_randombytes :: Ptr Word8 -> Word32 -> IO CInt

foreign import ccall "wallet_sodium_argon2id"
    wallet_sodium_argon2id :: Ptr Word8     -- derived wrapping key bytes
                           -> Word32
                           -> Ptr PassPhrase
                           -> Word32
                           -> Ptr Word8     -- 32 byte salt
                           -> Word32
                           -> Word64
                           -> IO CInt

foreign import ccall "wallet_sodium_xchacha20poly1305_encrypt"
    wallet_sodium_xchacha20poly1305_encrypt :: Ptr Word8 -- ciphertext
                                            -> Ptr Word8 -- tag
                                            -> Ptr Word8 -- plaintext
                                            -> Word32
                                            -> Ptr Word8 -- associated data
                                            -> Word32
                                            -> Ptr Word8 -- nonce
                                            -> Ptr Word8 -- key
                                            -> IO CInt

foreign import ccall "wallet_sodium_xchacha20poly1305_decrypt"
    wallet_sodium_xchacha20poly1305_decrypt :: Ptr Word8 -- plaintext
                                            -> Ptr Word8 -- ciphertext
                                            -> Word32
                                            -> Ptr Word8 -- tag
                                            -> Ptr Word8 -- associated data
                                            -> Word32
                                            -> Ptr Word8 -- nonce
                                            -> Ptr Word8 -- key
                                            -> IO CInt
