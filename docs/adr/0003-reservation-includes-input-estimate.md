# Spend reservation when max tokens is absent

The beta names two formulas: body bytes over four times the input price, plus `max_tokens` times the output price; and, when `max_tokens` is unset, `default_reservation_usd`.

The default replaces only the unknown output term. The input estimate is still held. Treating the whole reservation as $0.10 would let a large prompt slip past a small cap. Both the cap and the default are integer microdollars.
