# Mock statistical analysis script for K-Veritas integration testing.
#
# Demonstrates that kveritas works with R scripts identically to Python.
# The KVERITAS_METRIC format is just a printed line; any language works.
#
# Usage:
#   kveritas run --files tests/mock_analysis.R -- Rscript tests/mock_analysis.R

set.seed(42)

n <- 500
x <- rnorm(n)
y <- 2.3 * x + 0.5 + rnorm(n, sd = 0.4)

cat("Linear regression: n =", n, "\n")

fit <- lm(y ~ x)
s <- summary(fit)

r_squared   <- s$r.squared
adj_r2      <- s$adj.r.squared
rmse        <- sqrt(mean(s$residuals^2))
f_statistic <- s$fstatistic[1]
p_value     <- pf(s$fstatistic[1], s$fstatistic[2], s$fstatistic[3], lower.tail = FALSE)

cat("\nModel summary:\n")
cat(sprintf("  R-squared:   %.4f\n", r_squared))
cat(sprintf("  Adj R2:      %.4f\n", adj_r2))
cat(sprintf("  RMSE:        %.4f\n", rmse))
cat(sprintf("  F-statistic: %.4f\n", f_statistic))
cat(sprintf("  p-value:     %.6f\n", p_value))

# Emit KVERITAS_METRIC lines, identical format to Python.
cat(sprintf("KVERITAS_METRIC name=r_squared value=%.6f step=final\n", r_squared))
cat(sprintf("KVERITAS_METRIC name=adj_r_squared value=%.6f step=final\n", adj_r2))
cat(sprintf("KVERITAS_METRIC name=rmse value=%.6f step=final\n", rmse))
cat(sprintf("KVERITAS_METRIC name=f_statistic value=%.6f step=final\n", f_statistic))
cat(sprintf("KVERITAS_METRIC name=p_value value=%.8f step=final\n", p_value))

cat("\nAnalysis complete.\n")
