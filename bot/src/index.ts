import {
  encodeFunctionData,
  parseAbiParameters,
  encodeAbiParameters,
  encodePacked,
  getAbiItem,
  keccak256,
  parseGwei,
  createPublicClient,
  http,
  createWalletClient,
  getContract,
  zeroAddress,
  parseEther,
  toBytes,
} from "viem";
import { writeContract } from "viem/dist/types/actions/wallet/writeContract";
import { privateKeyToAccount } from "viem/accounts";
import { polygon } from "viem/chains";
import { EntryPointAbi } from "./abi/EntryPoint";
import { SimpleAccountFactoryAbi } from "./abi/SimpleAccountFactory";
import { SimpleAccountAbi } from "./abi/SimpleAccount";
import { ERC20Abi } from "./abi/ERC20";
import { WeenusAbi } from "./abi/Weenus";
import { SimplePaymasterAbi } from "./abi/SimplePaymaster";
import { UniswapRouterAbi } from "./abi/Uniswap";
import { readContract } from "viem/dist/types/actions/public/readContract";

type UserOperation = {
  sender: `0x${string}`;
  nonce: bigint;
  initCode: `0x${string}`;
  callData: `0x${string}`;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymasterAndData: `0x${string}`;
  signature?: `0x${string}`;
};

const getUserOpHash = (
  userOp: UserOperation,
  entryPointAddress: `0x${string}`,
  chainId: bigint
) => {
  const packed = encodeAbiParameters(
    parseAbiParameters(
      "address sender, uint256 nonce, bytes32 initCode, bytes32 callData, uint256 callGasLimit, uint256 verificationGasLimit, uint256 preVerificationGas, uint256 maxFeePerGas, uint256 maxPriorityFeePerGas, bytes32 paymasterAndData"
    ),
    [
      userOp.sender,
      userOp.nonce,
      keccak256(userOp.initCode),
      keccak256(userOp.callData),
      userOp.callGasLimit,
      userOp.verificationGasLimit,
      userOp.preVerificationGas,
      userOp.maxFeePerGas,
      userOp.maxPriorityFeePerGas,
      keccak256(userOp.paymasterAndData),
    ]
  );

  const enc = encodeAbiParameters(
    parseAbiParameters("bytes32 hashed, address entrypoint, uint256 chainId"),
    [keccak256(packed), entryPointAddress, chainId]
  );

  return keccak256(enc);
};

const cheapUser = privateKeyToAccount(
  "0x9d96e2c9193d7298c49ff0c4f31c9381d2891b550af609672f0106674ec7ac12"
);
const sponsor = privateKeyToAccount(
  (process.env["SPONSOR_PRIVATE_KEY"] as `0x${string}`) || keccak256("0x0")
);

const SIMPLE_PAYMASTER = "0x4D09c83162d7032C5eA4319EbC1C1E6858821246";
const WEENUS_ADDR = "0x6Db590ae1A42D37f1C2e365cbB7cB7536E5906Ef";
const QUICKSWAP_ADDR = "0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff";
const ENTRYPOINT_ADDR = "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789";
const SIMPLEACCFACTORY_ADDR = "0x19Fe133a5C488f3D36271402dF49EA48b2a9B9a5";

const walletClient = createWalletClient({
  account: sponsor,
  chain: polygon,
  transport: http(),
});

const publicClient = createPublicClient({
  chain: polygon,
  transport: http(),
});

const getInitCode = (
  simpleAccountFactoryAddress: `0x${string}`,
  eoaAddress: `0x${string}`
): `0x${string}` => {
  return `0x${simpleAccountFactoryAddress.replace(
    "0x",
    ""
  )}5fbfb9cf000000000000000000000000${eoaAddress.replace(
    "0x",
    ""
  )}0000000000000000000000000000000000000000000000000000000000000000`;
};

const main = async () => {
  const simpleAccountFactory = getContract({
    abi: SimpleAccountFactoryAbi,
    address: SIMPLEACCFACTORY_ADDR,
    publicClient,
    walletClient,
  });

  const entrypoint = getContract({
    abi: EntryPointAbi,
    address: ENTRYPOINT_ADDR,
    publicClient,
    walletClient,
  });

  const simplePaymaster = getContract({
    abi: SimplePaymasterAbi,
    address: SIMPLE_PAYMASTER,
    publicClient,
    walletClient,
  });

  // Prefund the paymaster
  // const tx = await entrypoint.write.depositTo([sponsor.address], {
  //   value: parseEther("1"), maxFeePerGas: parseGwei('150'), maxPriorityFeePerGas: parseGwei('30')
  // });
  // console.log('tx', tx)

  const chainId = await publicClient.getChainId();

  const sender = await simpleAccountFactory.read.getAddress([
    cheapUser.address,
    0n,
  ]);

  console.log("cheapUser", cheapUser.address);
  console.log("aa wallet", sender);

  const initCode = getInitCode(SIMPLEACCFACTORY_ADDR, cheapUser.address);

  const nonce = await publicClient
    .readContract({
      address: sender,
      abi: SimpleAccountAbi,
      functionName: "getNonce",
    })
    .catch(() => 0n);

  const dripCalldata = encodeFunctionData({
    abi: WeenusAbi,
    functionName: "drip",
  });

  const callData = encodeFunctionData({
    abi: SimpleAccountAbi,
    functionName: "execute",
    args: [WEENUS_ADDR, 0n, dripCalldata],
  });

  const userOp: UserOperation = {
    sender,
    nonce,
    initCode,
    callData,
    callGasLimit: 600000n,
    verificationGasLimit: 500000n,
    preVerificationGas: 500000n,
    maxFeePerGas: parseGwei("1"),
    maxPriorityFeePerGas: parseGwei("1"),
    paymasterAndData: SIMPLE_PAYMASTER,
  };

  const userOphash = getUserOpHash(userOp, ENTRYPOINT_ADDR, BigInt(chainId));
  const signature = await walletClient.signMessage({
    account: cheapUser,
    message: { raw: toBytes(userOphash) },
  });
  const userOpHashWithSig = { ...userOp, signature };

  const tx = await entrypoint.simulate.simulateValidation([userOpHashWithSig]).catch(x => x);

  // const tx = await entrypoint.write.handleOps(
  //   [[userOpHashWithSig], sponsor.address],
  //   {
  //     gas: 5000000n,
  //     maxFeePerGas: parseGwei("150"),
  //     maxPriorityFeePerGas: parseGwei("35"),
  //   }
  // );

  console.log("tx", tx);
  // console.log("sender", sender);

  // await walletClient.writeContract({
  //   address: SIMPLEACCFACTORY_ADDR,
  //   abi: SimpleAccountFactoryAbi,
  //   functionName: "createAccount",
  //   args: [sponsor.address, 0n],
  //   nonce: 2,
  //   maxPriorityFeePerGas: parseGwei("1"),
  // });

  // console.log("here here");
};
main();
