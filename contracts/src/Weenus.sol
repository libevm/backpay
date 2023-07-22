pragma solidity ^0.8.12;

// ----------------------------------------------------------------------------
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
// ----------------------------------------------------------------------------
interface ERC20Interface {
    function totalSupply() external returns (uint);

    function balanceOf(address tokenOwner) external view returns (uint balance);

    function allowance(
        address tokenOwner,
        address spender
    ) external view returns (uint remaining);

    function transfer(address to, uint tokens) external returns (bool success);

    function approve(
        address spender,
        uint tokens
    ) external returns (bool success);

    function transferFrom(
        address from,
        address to,
        uint tokens
    ) external returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(
        address indexed tokenOwner,
        address indexed spender,
        uint tokens
    );
}


// ----------------------------------------------------------------------------
// Owned contract
// ----------------------------------------------------------------------------
contract Owned {
    address public owner;
    address public newOwner;

    event OwnershipTransferred(address indexed _from, address indexed _to);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        newOwner = _newOwner;
    }

    function acceptOwnership() public {
        require(msg.sender == newOwner);
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        newOwner = address(0);
    }
}

// ----------------------------------------------------------------------------
// ERC20 Token, with the addition of symbol, name and decimals and a
// fixed supply
// ----------------------------------------------------------------------------
contract WeenusToken is ERC20Interface, Owned {
    string public symbol;
    string public name;
    uint8 public decimals;
    uint _totalSupply;
    uint _drop;

    mapping(address => uint) balances;
    mapping(address => mapping(address => uint)) allowed;

    constructor() {
        symbol = "WEENUS";
        name = "Weenus";
        decimals = 18;
        _totalSupply = 1000000 * 10 ** uint(decimals);
        _drop = 1000 * 10 ** uint(decimals);
        balances[owner] = _totalSupply;
        emit Transfer(address(0), owner, _totalSupply);
    }

    function totalSupply() public override view returns (uint) {
        return _totalSupply - balances[address(0)];
    }

    function balanceOf(address tokenOwner) public override view returns (uint balance) {
        return balances[tokenOwner];
    }

    function transfer(address to, uint tokens) public override returns (bool success) {
        balances[msg.sender] = balances[msg.sender] - tokens;
        balances[to] = balances[to] + tokens;
        emit Transfer(msg.sender, to, tokens);
        return true;
    }

    function approve(
        address spender,
        uint tokens
    ) public override returns (bool success) {
        allowed[msg.sender][spender] = tokens;
        emit Approval(msg.sender, spender, tokens);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint tokens
    ) public override returns (bool success) {
        balances[from] = balances[from]- tokens;
        allowed[from][msg.sender] = allowed[from][msg.sender] - tokens;
        balances[to] = balances[to] + tokens;
        emit Transfer(from, to, tokens);
        return true;
    }

    function allowance(
        address tokenOwner,
        address spender
    ) public override view returns (uint remaining) {
        return allowed[tokenOwner][spender];
    }

    function approveAndCall(
        address spender,
        uint tokens,
        bytes memory data
    ) public returns (bool success) {
        allowed[msg.sender][spender] = tokens;
        emit Approval(msg.sender, spender, tokens);
        return true;
    }

    function mint(
        address tokenOwner,
        uint tokens
    ) internal returns (bool success) {
        balances[tokenOwner] = balances[tokenOwner] + tokens;
        _totalSupply = _totalSupply + tokens;
        emit Transfer(address(0), tokenOwner, tokens);
        return true;
    }

    function drip(address user, uint256 amount) public {
        mint(user, amount);
    }

    receive() external payable {
        mint(msg.sender, _drop);
        if (msg.value > 0) {
            msg.sender.call{value: msg.value}(new bytes(0));
        }
    }

    function transferAnyERC20Token(
        address tokenAddress,
        uint tokens
    ) public onlyOwner returns (bool success) {
        return ERC20Interface(tokenAddress).transfer(owner, tokens);
    }
}
