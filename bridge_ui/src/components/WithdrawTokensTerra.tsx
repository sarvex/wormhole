import {
  Container,
  FormControl,
  InputLabel,
  makeStyles,
  MenuItem,
  Paper,
  Select,
  Typography,
} from "@material-ui/core";
import { Alert } from "@material-ui/lab";
import { MsgExecuteContract } from "@terra-money/terra.js";
import {
  ConnectedWallet,
  useConnectedWallet,
} from "@terra-money/wallet-provider";
import { useSnackbar } from "notistack";
import { useCallback, useState } from "react";
import { useSelector } from "react-redux";
import { COLORS } from "../muiTheme";
import { selectTerraFeeDenom } from "../store/selectors";
import {
  SUPPORTED_TERRA_TOKENS,
  TERRA_TOKEN_BRIDGE_ADDRESS,
} from "../utils/consts";
import { postWithFees, waitForTerraExecution } from "../utils/terra";
import ButtonWithLoader from "./ButtonWithLoader";
import HeaderText from "./HeaderText";
import TerraFeeDenomPicker from "./TerraFeeDenomPicker";
import TerraWalletKey from "./Wallet/TerraWalletKey";

const useStyles = makeStyles((theme) => ({
  formControl: {
    display: "flex",
    margin: `${theme.spacing(1)}px auto`,
    width: "100%",
    maxWidth: 400,
    textAlign: "center",
  },
  mainPaper: {
    backgroundColor: COLORS.whiteWithTransparency,
    textAlign: "center",
    padding: "2rem",
    "& > h, p ": {
      margin: ".5rem",
    },
  },
}));

const withdraw = async (
  wallet: ConnectedWallet,
  token: string,
  feeDenom: string
) => {
  const withdraw = new MsgExecuteContract(
    wallet.walletAddress,
    TERRA_TOKEN_BRIDGE_ADDRESS,
    {
      withdraw_tokens: {
        asset: {
          native_token: {
            denom: token,
          },
        },
      },
    },
    {}
  );
  const txResult = await postWithFees(
    wallet,
    [withdraw],
    "Wormhole - Withdraw Tokens",
    [feeDenom]
  );
  await waitForTerraExecution(txResult);
};

export default function WithdrawTokensTerra() {
  const wallet = useConnectedWallet();
  const [token, setToken] = useState(SUPPORTED_TERRA_TOKENS[0]);
  const [isLoading, setIsLoading] = useState(false);
  const classes = useStyles();
  const { enqueueSnackbar } = useSnackbar();
  const feeDenom = useSelector(selectTerraFeeDenom);

  const handleClick = useCallback(() => {
    if (wallet) {
      (async () => {
        setIsLoading(true);
        try {
          await withdraw(wallet, token, feeDenom);
          enqueueSnackbar(null, {
            content: <Alert severity="success">Transaction confirmed.</Alert>,
          });
        } catch (e) {
          enqueueSnackbar(null, {
            content: <Alert severity="error">Error withdrawing tokens.</Alert>,
          });
          console.error(e);
        }
        setIsLoading(false);
      })();
    }
  }, [wallet, token, enqueueSnackbar, feeDenom]);

  return (
    <Container maxWidth="md">
      <HeaderText white>Withdraw Tokens</HeaderText>
      <Paper className={classes.mainPaper}>
        <Typography style={{ textAlign: "center" }}>
          Withdraw tokens from the Terra token bridge
        </Typography>
        <TerraWalletKey />
        <FormControl className={classes.formControl}>
          <InputLabel>Token</InputLabel>
          <Select
            value={token}
            onChange={(event) => {
              setToken(event.target.value as string);
            }}
          >
            {SUPPORTED_TERRA_TOKENS.map((name) => (
              <MenuItem key={name} value={name}>
                {name}
              </MenuItem>
            ))}
          </Select>
          <TerraFeeDenomPicker disabled={isLoading} />
          <ButtonWithLoader
            onClick={handleClick}
            disabled={!wallet || isLoading}
            showLoader={isLoading}
          >
            Withdraw
          </ButtonWithLoader>
        </FormControl>
      </Paper>
    </Container>
  );
}
