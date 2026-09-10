# Codey Rocky IR Communication

Official Makeblock documentation states:

> `ir.send(str)`
> Send infrared string. Parameters:
> - `str`: The string data to be emitted. The function `send` will add the `\n` terminator at the end of the string automatically.

However, that does not describe the underlying reality of the protocol implementation over the air.

### What `ir.send(str)` Actually Does:
1. Takes the input string and appends a `\n` (`0x0A`) newline character.
2. Splits the string into individual character bytes.
3. Transmits **each character as a separate, full 32-bit NEC protocol packet**.

---

## How I Figured It Out

I wrote a small JavaScript script for Bruce (running on my LilyGo T-Embed) to record raw IR pulse timings, similar to how a Flipper Zero captures raw signals.

A raw signal stream for a transmitted string looks like this:

```text
Raw Signals: 8870 4568 510 646 460 644 462 672 460 696 406 622 510 672 458 620 482 648 482 1832 406 1776 486 1776 460 1800 484 1724 488 1802 482 1780 432 1776 486 618 482 1752 510 1726 512 1750 508 620 484 1750 512 1776 456 702 460 1698 536 646 458 594 538 672 430 1754 510 648 484 592 512 1750 512 32826 8930 4594 456 646 458 726 406
```

We can see:
 - AGC Header ~13.5 ms ($9000\,\mu\text{s} + 4500\,\mu\text{s}$)
 - 32 0s and 1s ($500\,\mu\text{s} $1600\,\mu\text{s})
 - 32ms end of packet

That looks like a NEC protocol specially if you translate to 1s and 0s and see that 1st is inverse of 2nd byte and 3rd is inverse of 4th
So knowing what text I'm sending I confirmed that 3rd bytes only is the single character and bits are Reverse in each individual 8-bit byte array (LSB -> MSB).
So in conclusion: 
`ir.send(str)`
1. Takes the input string and appends a `\n` (`0x0A`) newline character.
2. Splits the string into individual character bytes.
3. Transmits **each character as a separate, full 32-bit NEC protocol packet**.

```
Raw Packet: 8846 4674 430 596 484 672 430 624 508 648 462 644 482 700 406 644 486 672 434 1880 378 1778 484 1830 408 1804 454 1778 460 1778 484 1752 538 1724 484 1832 406 1776 482 1728 616 486 540 646 456 1808 454 1806 432 594 588 542 508 648 456 648 482 1832 432 1752 510 620 480 624 508 1806 432 32828
Extracted Bits: 00000000111111110110011110011000
Hex Bytes: 00 FF 67 98
Raw Packet: 8928 4622 456 646 460 644 488 618 482 648 484 672 432 646 484 646 460 668 408 1804 510 1754 480 1752 510 1778 460 1778 510 1856 352 1728 560 1728 510 1752 484 644 456 1804 454 596 514 672 460 1802 456 1754 484 618 482 648 512 1722 536 596 484 1750 508 1756 480 672 458 594 564 1672 590 32802
Extracted Bits: 00000000111111110110010110011010
Hex Bytes: 00 FF 65 9A
Raw Packet: 8904 4566 482 700 456 594 538 568 512 670 456 596 510 646 458 620 512 620 512 1750 484 1752 510 1776 462 1722 536 1754 484 1776 486 1748 484 1778 486 1776 486 566 536 1726 512 594 558 548 532 1728 540 1722 510 644 512 594 508 1728 510 618 512 1750 482 1756 538 564 512 618 512 1776 508 32728
Extracted Bits: 00000000111111110110010110011010
Hex Bytes: 00 FF 65 9A
```