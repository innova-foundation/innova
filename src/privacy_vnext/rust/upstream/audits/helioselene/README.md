# Helios/Selene (Helioselene)

tevador proposed Helios and Selene in a [GitHub Gist](
  https://gist.github.com/tevador/4524c2092178df08996487d4e272b096
). The curves were found using a Sage script, Helios and Selene being the first
pair of elliptic curves to:

- Have a 255-bit $q$
- Have $3 \cong 4 \mod q$
- Have $(2^{256} \mod q) < 2^{128}$
- Have a secure twist

The [script is included in this repository](script/) under the stated license.

The Monero project [sponsored a competition](
  https://github.com/j-berman/fcmp-plus-plus-optimization-competition
) for an efficient implementation, which has been optimized and improved since.

The Monero project had Veridise review the choice of curves, leading to the
chosen curve being updated to the one _currently_ described in the Gist and as
detailed above. The original nomination lacked a secure twist, which was deemed
a concern not worth having when an option with a secure twist could be easily
chosen instead.

Veridise was then contracted to perform formal verification of the
[`helioselene`](/crypto/helioselene) library implementing these curves, yet
only verified some functions due to time constraints. For more information on
this, please see the library's [README](/crypto/helioselene/README.md).
